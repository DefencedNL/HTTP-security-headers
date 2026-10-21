#!/usr/bin/env python3
"""
securityheaders.py — standalone HTTP security header checker.

Checks the response headers of one or more URLs against the common
security-header checklist (similar in spirit to securityheaders.com), grades
each result, and prints a report plus a summary table. Does NOT depend on any
third-party scraping — it talks to the targets directly via `requests`.

Usage:
    python3 securityheaders.py <URL> [<URL> ...]
    python3 securityheaders.py -f urls.txt                # one URL per line
    cat urls.txt | python3 securityheaders.py -f -        # read from stdin
    python3 securityheaders.py -f urls.txt --summary      # summary table only
    python3 securityheaders.py -f urls.txt --csv out.csv  # spreadsheet export
    python3 securityheaders.py -f urls.txt --json         # machine-readable output
    python3 securityheaders.py -f urls.txt --no-verify    # skip TLS verification

Input file format:
    One URL per line. Blank lines and lines starting with # are ignored.
    Entries without a scheme get https:// prepended. Duplicates are skipped.

Proxy support:
    Honors the standard http_proxy / https_proxy / HTTP_PROXY / HTTPS_PROXY
    environment variables automatically (requests reads these natively).
"""

import argparse
import csv
import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

import requests
import urllib3

# ---------------------------------------------------------------------------
# Header definitions
# ---------------------------------------------------------------------------

# Each entry: header name -> (weight, description, evaluator)
# evaluator(value) -> (status, note)  where status in {"good", "warn", "bad"}

def eval_hsts(value):
    if value is None:
        return "bad", "Missing — site is not enforcing HTTPS via HSTS."
    v = value.lower()
    if "max-age" not in v:
        return "warn", "Present but missing max-age directive."
    try:
        max_age = int(v.split("max-age=")[1].split(";")[0].strip())
    except (IndexError, ValueError):
        return "warn", "Present but max-age could not be parsed."
    if max_age < 15552000:  # 180 days, common recommended floor
        return "warn", f"max-age is low ({max_age}s); recommend >= 15552000 (180 days)."
    note = "Looks solid."
    if "includesubdomains" not in v:
        note += " Consider adding includeSubDomains."
    if "preload" not in v:
        note += " Consider adding preload."
    return "good", note


def eval_csp(value):
    if value is None:
        return "bad", "Missing — no restriction on where scripts/styles/etc. can load from."
    v = value.lower()
    if "unsafe-inline" in v or "unsafe-eval" in v:
        return "warn", "Present but allows 'unsafe-inline' or 'unsafe-eval', weakening protection."
    if v.strip() in ("", "none"):
        return "warn", "Present but effectively empty."
    return "good", "Present and does not use unsafe-inline/unsafe-eval."


def eval_xfo(value):
    if value is None:
        return "warn", "Missing — clickjacking protection relies on CSP frame-ancestors instead, if set."
    v = value.lower()
    if v in ("deny", "sameorigin"):
        return "good", f"Set to {value}."
    return "warn", f"Set to an unusual value: {value}"


def eval_xcto(value):
    if value is None:
        return "bad", "Missing — browsers may MIME-sniff responses."
    if value.lower() == "nosniff":
        return "good", "Set to nosniff."
    return "warn", f"Set to an unexpected value: {value}"


def eval_referrer(value):
    if value is None:
        return "warn", "Missing — defaults to browser policy (varies)."
    good_values = {
        "no-referrer", "no-referrer-when-downgrade", "same-origin",
        "strict-origin", "strict-origin-when-cross-origin",
    }
    if value.lower() in good_values:
        return "good", f"Set to {value}."
    return "warn", f"Set to a permissive/unusual value: {value}"


def eval_permissions_policy(value):
    if value is None:
        return "warn", "Missing — browser features (camera, geolocation, etc.) not explicitly restricted."
    return "good", "Present."


def eval_coop(value):
    if value is None:
        return "warn", "Missing — no cross-origin window isolation."
    return "good", f"Set to {value}."


def eval_corp(value):
    if value is None:
        return "warn", "Missing — no cross-origin resource policy set."
    return "good", f"Set to {value}."


def eval_coep(value):
    if value is None:
        return "warn", "Missing — no cross-origin embedder policy set."
    return "good", f"Set to {value}."


def eval_server(value):
    # Informational, not a pass/fail
    if value is None:
        return "good", "Not disclosed."
    return "warn", f"Discloses server software: {value}"


def eval_powered_by(value):
    if value is None:
        return "good", "Not disclosed."
    return "warn", f"Discloses backend technology: {value}"


CHECKS = [
    ("Strict-Transport-Security", 20, eval_hsts),
    ("Content-Security-Policy", 20, eval_csp),
    ("X-Frame-Options", 10, eval_xfo),
    ("X-Content-Type-Options", 10, eval_xcto),
    ("Referrer-Policy", 10, eval_referrer),
    ("Permissions-Policy", 10, eval_permissions_policy),
    ("Cross-Origin-Opener-Policy", 5, eval_coop),
    ("Cross-Origin-Resource-Policy", 5, eval_corp),
    ("Cross-Origin-Embedder-Policy", 5, eval_coep),
]

# Informational-only headers (do not count toward the score)
INFO_CHECKS = [
    ("Server", eval_server),
    ("X-Powered-By", eval_powered_by),
]

# Short names for the summary table
SHORT_NAMES = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "CSP",
    "X-Frame-Options": "XFO",
    "X-Content-Type-Options": "XCTO",
    "Referrer-Policy": "Referrer",
    "Permissions-Policy": "Permissions",
    "Cross-Origin-Opener-Policy": "COOP",
    "Cross-Origin-Resource-Policy": "CORP",
    "Cross-Origin-Embedder-Policy": "COEP",
}

STATUS_POINTS = {"good": 1.0, "warn": 0.5, "bad": 0.0}

ANSI = {
    "good": "\033[32m",   # green
    "warn": "\033[33m",   # yellow
    "bad": "\033[31m",    # red
    "info": "\033[36m",   # cyan
    "bold": "\033[1m",
    "reset": "\033[0m",
    "dim": "\033[2m",
}
COLOR = dict(ANSI)  # replaced with empty strings when color is disabled

SYMBOL = {"good": "[+]", "warn": "[~]", "bad": "[-]"}


def grade_from_score(pct):
    if pct >= 90:
        return "A"
    if pct >= 80:
        return "B"
    if pct >= 65:
        return "C"
    if pct >= 50:
        return "D"
    return "F"


# ---------------------------------------------------------------------------
# Input
# ---------------------------------------------------------------------------

def normalize_url(entry):
    url = entry.strip()
    if not urlparse(url).scheme:
        url = "https://" + url
    return url


def load_urls(positional, file_arg):
    raw = list(positional)
    if file_arg:
        try:
            fh = sys.stdin if file_arg == "-" else open(file_arg, encoding="utf-8-sig")
        except OSError as e:
            sys.exit(f"Cannot read {file_arg}: {e}")
        with fh:
            for line in fh:
                line = line.strip()      # also removes Windows \r line endings
                if line and not line.startswith("#"):
                    raw.append(line)

    urls, seen = [], set()
    for entry in raw:
        url = normalize_url(entry)
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


# ---------------------------------------------------------------------------
# Fetching and analysis
# ---------------------------------------------------------------------------

def fetch(url, timeout, verify, no_redirect):
    headers = {
        "User-Agent": "securityheaders.py/1.1 (local header checker)"
    }
    resp = requests.get(
        url,
        headers=headers,
        timeout=timeout,
        verify=verify,
        allow_redirects=not no_redirect,
        stream=True,          # headers only; don't download large bodies
    )
    resp.close()
    return resp


def analyze(resp):
    # Response headers are case-insensitive in requests (CaseInsensitiveDict)
    h = resp.headers

    results = []
    total_weight = 0
    earned = 0.0

    for name, weight, evaluator in CHECKS:
        value = h.get(name)
        status, note = evaluator(value)
        results.append({
            "header": name,
            "value": value,
            "status": status,
            "note": note,
            "weight": weight,
        })
        total_weight += weight
        earned += STATUS_POINTS[status] * weight

    info_results = []
    for name, evaluator in INFO_CHECKS:
        value = h.get(name)
        status, note = evaluator(value)
        info_results.append({
            "header": name,
            "value": value,
            "status": status,
            "note": note,
        })

    pct = (earned / total_weight * 100) if total_weight else 0
    grade = grade_from_score(pct)

    return {
        "url": resp.url,
        "status_code": resp.status_code,
        "score_pct": round(pct, 1),
        "grade": grade,
        "checks": results,
        "info": info_results,
        "all_headers": dict(h),
    }


def short_reason(exc):
    """Pull the useful part out of requests' long, nested error messages."""
    msg = str(exc)
    for pattern in (r"certificate verify failed[^'\")]*",
                    r"\[Errno -?\d+\][^'\")]*",
                    r"\[SSL[^\]]*\][^'\")]*"):
        found = re.findall(pattern, msg)
        if found:
            return found[-1].strip()
    return msg[:200]


def check_url(url, args):
    """Fetch and analyze one URL; errors are returned in the report, not raised."""
    report = {"input_url": url, "error": None}
    try:
        resp = fetch(url, args.timeout, verify=not args.no_verify, no_redirect=args.no_redirect)
    except requests.exceptions.SSLError as e:
        report["error"] = f"TLS error: {short_reason(e)} (try --no-verify for lab/self-signed targets)"
    except requests.exceptions.ConnectionError as e:
        report["error"] = f"Connection error: {short_reason(e)}"
    except requests.exceptions.Timeout:
        report["error"] = f"Timed out after {args.timeout}s"
    except requests.exceptions.RequestException as e:
        report["error"] = f"Request failed: {e}"
    else:
        report.update(analyze(resp))
    return report


# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------

def grade_color(grade):
    c = COLOR
    if grade in ("A", "B"):
        return c["good"]
    return c["warn"] if grade == "C" else c["bad"]


def print_report(report, show_all_headers):
    c = COLOR
    print(f"\n{c['bold']}Security Header Report{c['reset']}")
    if report["error"]:
        print(f"URL:          {report['input_url']}")
        print(f"{c['bad']}Error:        {report['error']}{c['reset']}\n")
        return

    print(f"URL:          {report['url']}")
    if report["url"] != report["input_url"]:
        print(f"Requested:    {report['input_url']} (redirected)")
    print(f"HTTP Status:  {report['status_code']}")
    print(f"Score:        {report['score_pct']}%   Grade: "
          f"{grade_color(report['grade'])}{c['bold']}{report['grade']}{c['reset']}")
    print()
    print(f"{c['bold']}Security Headers{c['reset']}")
    print("-" * 70)
    for item in report["checks"]:
        sym = SYMBOL[item["status"]]
        col = c[item["status"]]
        print(f"{col}{sym} {item['header']:<30}{c['reset']} {item['note']}")
        if item["value"]:
            shown = item["value"] if len(item["value"]) <= 90 else item["value"][:87] + "..."
            print(f"    {c['dim']}value: {shown}{c['reset']}")

    print()
    print(f"{c['bold']}Informational{c['reset']}")
    print("-" * 70)
    for item in report["info"]:
        sym = SYMBOL[item["status"]]
        col = c[item["status"]]
        print(f"{col}{sym} {item['header']:<30}{c['reset']} {item['note']}")

    if show_all_headers:
        print()
        print(f"{c['bold']}All Response Headers{c['reset']}")
        print("-" * 70)
        for k, v in report["all_headers"].items():
            print(f"{k}: {v}")

    print()


def print_summary(reports):
    c = COLOR
    print(f"\n{c['bold']}Summary ({len(reports)} URL(s)){c['reset']}")
    print("-" * 100)
    print(f"{'GRADE':<6} {'SCORE':>6}  {'HTTP':<4}  {'URL':<45} MISSING")
    for r in reports:
        if r["error"]:
            print(f"{c['bad']}{'ERR':<6}{c['reset']} {'-':>6}  {'-':<4}  {r['input_url']:<45} "
                  f"{c['dim']}{r['error'][:60]}{c['reset']}")
            continue
        missing = [SHORT_NAMES[i["header"]] for i in r["checks"] if i["value"] is None]
        print(f"{grade_color(r['grade'])}{r['grade']:<6}{c['reset']} {r['score_pct']:>5}%  "
              f"{r['status_code']:<4}  {r['url']:<45} {', '.join(missing) or '-'}")

    graded = [r for r in reports if not r["error"]]
    counts = {g: sum(1 for r in graded if r["grade"] == g) for g in "ABCDF"}
    print("-" * 100)
    print("Grades: " + "  ".join(f"{g}={n}" for g, n in counts.items())
          + f"  errors={len(reports) - len(graded)}\n")


def write_csv(reports, path):
    fields = (["input_url", "final_url", "status_code", "grade", "score_pct", "error"]
              + [name for name, _, _ in CHECKS]
              + [name for name, _ in INFO_CHECKS])
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields)
        writer.writeheader()
        for r in reports:
            row = {"input_url": r["input_url"], "error": r["error"] or ""}
            if not r["error"]:
                row.update(final_url=r["url"], status_code=r["status_code"],
                           grade=r["grade"], score_pct=r["score_pct"])
                for item in r["checks"]:
                    row[item["header"]] = item["status"]
                for item in r["info"]:
                    row[item["header"]] = item["value"] or ""
            writer.writerow(row)


def main():
    parser = argparse.ArgumentParser(
        description="Check the HTTP security headers of one or more URLs and grade the results."
    )
    parser.add_argument("urls", nargs="*", help="Target URL(s), e.g. https://example.com")
    parser.add_argument("-f", "--file", help="Text file with one URL per line ('-' reads stdin)")
    parser.add_argument("-t", "--threads", type=int, default=5,
                        help="Number of URLs checked in parallel (default: 5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    parser.add_argument("--all-headers", action="store_true", help="Also print every raw response header")
    parser.add_argument("--summary", action="store_true", help="Only print the summary table")
    parser.add_argument("--csv", metavar="FILE", help="Write a per-URL summary to a CSV file")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of a report")
    parser.add_argument("--no-color", action="store_true", help="Disable colored output")
    args = parser.parse_args()

    urls = load_urls(args.urls, args.file)
    if not urls:
        parser.error("no URLs given (pass them as arguments or use -f FILE)")

    if args.no_color or not sys.stdout.isatty():
        COLOR.update({k: "" for k in COLOR})

    if args.no_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if len(urls) > 1 and not args.json:
        print(f"Checking {len(urls)} URL(s)...", file=sys.stderr)

    # pool.map keeps the results in the same order as the input file
    with ThreadPoolExecutor(max_workers=max(1, args.threads)) as pool:
        reports = list(pool.map(lambda u: check_url(u, args), urls))

    if args.json:
        print(json.dumps(reports[0] if len(reports) == 1 else reports, indent=2))
    else:
        if not args.summary:
            for report in reports:
                print_report(report, show_all_headers=args.all_headers)
        if len(reports) > 1 or args.summary:
            print_summary(reports)

    if args.csv:
        write_csv(reports, args.csv)
        print(f"CSV written to {args.csv}", file=sys.stderr)

    # Non-zero exit only if every URL failed
    sys.exit(1 if all(r["error"] for r in reports) else 0)


if __name__ == "__main__":
    main()
