#!/usr/bin/env python3
"""
securityheaders.py — standalone HTTP security header checker.

Checks a target URL's response headers against the common security-header
checklist (similar in spirit to securityheaders.com), grades the result,
and prints a report. Does NOT depend on any third-party scraping — it
talks to the target directly via `requests`.

Usage:
    python3 securityheaders.py <URL>
    python3 securityheaders.py <URL> --no-verify        # skip TLS verification
    python3 securityheaders.py <URL> --timeout 15
    python3 securityheaders.py <URL> --json             # machine-readable output

Proxy support:
    Honors the standard http_proxy / https_proxy / HTTP_PROXY / HTTPS_PROXY
    environment variables automatically (requests reads these natively).
"""

import argparse
import json
import sys
import urllib3
from urllib.parse import urlparse

import requests

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

STATUS_POINTS = {"good": 1.0, "warn": 0.5, "bad": 0.0}

COLOR = {
    "good": "\033[32m",   # green
    "warn": "\033[33m",   # yellow
    "bad": "\033[31m",    # red
    "info": "\033[36m",   # cyan
    "bold": "\033[1m",
    "reset": "\033[0m",
    "dim": "\033[2m",
}

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


def fetch(url, timeout, verify, no_redirect):
    headers = {
        "User-Agent": "securityheaders.py/1.0 (local header checker)"
    }
    resp = requests.get(
        url,
        headers=headers,
        timeout=timeout,
        verify=verify,
        allow_redirects=not no_redirect,
    )
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


def print_report(report, show_all_headers):
    c = COLOR
    print(f"\n{c['bold']}Security Header Report{c['reset']}")
    print(f"URL:          {report['url']}")
    print(f"HTTP Status:  {report['status_code']}")
    grade_color = c["good"] if report["grade"] in ("A", "B") else (
        c["warn"] if report["grade"] == "C" else c["bad"]
    )
    print(f"Score:        {report['score_pct']}%   Grade: {grade_color}{c['bold']}{report['grade']}{c['reset']}")
    print()
    print(f"{c['bold']}Security Headers{c['reset']}")
    print("-" * 70)
    for item in report["checks"]:
        sym = SYMBOL[item["status"]]
        col = c[item["status"]]
        header_display = f"{item['header']}"
        print(f"{col}{sym} {header_display:<30}{c['reset']} {item['note']}")
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


def main():
    parser = argparse.ArgumentParser(
        description="Check a URL's HTTP security headers and grade the result."
    )
    parser.add_argument("url", help="Target URL, e.g. https://example.com")
    parser.add_argument("--timeout", type=float, default=10.0, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--no-redirect", action="store_true", help="Do not follow redirects")
    parser.add_argument("--all-headers", action="store_true", help="Also print every raw response header")
    parser.add_argument("--json", action="store_true", help="Output machine-readable JSON instead of a report")
    args = parser.parse_args()

    url = args.url
    if not urlparse(url).scheme:
        url = "https://" + url

    if args.no_verify:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    try:
        resp = fetch(url, args.timeout, verify=not args.no_verify, no_redirect=args.no_redirect)
    except requests.exceptions.SSLError as e:
        print(f"TLS error connecting to {url}: {e}\nTry --no-verify if this is a lab/self-signed target.", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.ConnectionError as e:
        print(f"Connection error reaching {url}: {e}", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"Request to {url} timed out after {args.timeout}s.", file=sys.stderr)
        sys.exit(1)
    except requests.exceptions.RequestException as e:
        print(f"Request failed: {e}", file=sys.stderr)
        sys.exit(1)

    report = analyze(resp)

    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_report(report, show_all_headers=args.all_headers)


if __name__ == "__main__":
    main()
