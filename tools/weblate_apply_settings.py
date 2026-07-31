#!/usr/bin/env python3
"""Apply translation-workflow settings to every Weblate component in the project.

Weblate's linked components (the 70 plugins linked to Core) do NOT inherit
per-component translation-workflow settings - "Adding new translation",
"Turn on suggestions", "Suggestion voting" have to be set on each component.
Doing that by hand across ~71 components is error-prone; this does it over the
REST API, idempotently.

It is a **dry run by default**: it lists what it WOULD change and writes
nothing. Re-run with APPLY=1 to actually PATCH the components. A component
already matching the desired settings is reported and skipped (no write).

Desired settings live in DESIRED below - edit that to change what is applied.
Current defaults restrict language creation to a maintainer request and enable
community suggestions + voting:

  new_lang           = "contact"  (Adding new translation -> Contact maintainers)
  enable_suggestions = True       (Turn on suggestions)
  suggestion_voting  = True       (Suggestion voting)

Environment (same as tools/weblate_sync_components.py):
  WEBLATE_URL        base URL, e.g. https://translate.dcvault.net   (required)
  WEBLATE_API_TOKEN  a Weblate API token (Settings -> API access)   (required)
  WEBLATE_PROJECT    project slug                    (default: luadch-ng)
  APPLY=1            actually write (otherwise dry run)
  WEBLATE_ONE=<slug> restrict to one component (diagnose without a wall of output)

Run from anywhere. Exit code 0 = all good, 1 = at least one failure.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

URL = os.environ.get("WEBLATE_URL", "").rstrip("/")
TOKEN = os.environ.get("WEBLATE_API_TOKEN", "")
PROJECT = os.environ.get("WEBLATE_PROJECT") or "luadch-ng"
APPLY = os.environ.get("APPLY", "") not in ("", "0", "false", "False")

# The settings to enforce on every component. Edit here to change policy.
DESIRED = {
    "new_lang": "contact",
    "enable_suggestions": True,
    "suggestion_voting": True,
}

if not URL or not TOKEN:
    sys.exit("error: WEBLATE_URL and WEBLATE_API_TOKEN must be set")

COMPONENTS = f"{URL}/api/projects/{PROJECT}/components/"
# Weblate uses TWO different URL shapes: the project-scoped endpoint above lists
# components (GET) and creates them (POST), but a single component's detail -
# including PATCH to edit its settings - lives at a DIFFERENT path:
# /api/components/<project>/<slug>/. Using the list path for PATCH 404s.
COMPONENT_DETAIL = f"{URL}/api/components/{PROJECT}"  # + /<slug>/

# Test-run a single component by slug (e.g. WEBLATE_ONE=core-hub) to get one
# clean line of output instead of a wall of errors while diagnosing.
ONLY = os.environ.get("WEBLATE_ONE", "").strip()


def short(resp):
    """One-line summary of a response body so an error is diagnosable, not a
    50k-char dump. Only the actual Cloudflare interstitial ("Just a moment...")
    is a challenge; the `challenge-platform` script Cloudflare injects into
    NORMAL pages (incl. 404s) is NOT one - do not flag on that alone, or a plain
    404 gets misread as a Cloudflare block (the bug that hid a wrong PATCH URL)."""
    s = resp if isinstance(resp, str) else json.dumps(resp)
    low = s.lower()
    if "just a moment" in low or "attention required" in low:
        return ("Cloudflare challenge page - this request was actually challenged "
                "by Cloudflare (not just proxied)")
    if "<!doctype html" in low or "<html" in low:
        return "HTML page (not JSON): " + " ".join(s.split())[:200]
    return " ".join(s.split())[:300]

# A browser-like User-Agent - urllib's default is served the Cloudflare
# "Just a moment..." challenge on translate.dcvault.net (see weblate_sync_components.py).
USER_AGENT = os.environ.get(
    "WEBLATE_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36",
)


def api(method, url, data=None):
    """Return (status_code, parsed_or_text). JSON body when data is given."""
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Token {TOKEN}")
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    # Force an uncompressed body so an error page is readable text, not bytes.
    req.add_header("Accept-Encoding", "identity")
    if body is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, str(e)


def all_components():
    comps, nxt = [], COMPONENTS + "?page_size=100"
    while nxt:
        status, page = api("GET", nxt)
        if status == 404:
            sys.exit(f"error: project '{PROJECT}' not found (404) - check WEBLATE_PROJECT")
        if status != 200 or not isinstance(page, dict):
            sys.exit(f"error: listing components failed ({status}): {short(page)}")
        comps.extend(page.get("results", []))
        nxt = page.get("next")
    return comps


def main():
    comps = all_components()
    if not comps:
        sys.exit(f"error: no components found in project '{PROJECT}'")
    if ONLY:
        comps = [c for c in comps if c["slug"] == ONLY]
        if not comps:
            sys.exit(f"error: component '{ONLY}' not found (WEBLATE_ONE)")

    print(f"project: {PROJECT}   components: {len(comps)}   "
          f"mode: {'APPLY' if APPLY else 'DRY RUN (set APPLY=1 to write)'}")
    print(f"desired: {DESIRED}\n")

    updated = ok = failed = 0
    for c in comps:
        slug = c["slug"]
        # A linked component's own settings are returned on its object; compute
        # only the fields that actually differ so we skip no-op writes.
        diff = {k: v for k, v in DESIRED.items() if c.get(k) != v}
        if not diff:
            ok += 1
            continue
        change = ", ".join(f"{k}: {c.get(k)!r} -> {v!r}" for k, v in diff.items())
        if not APPLY:
            print(f"would update  {slug}: {change}")
            updated += 1
            continue
        status, resp = api("PATCH", f"{COMPONENT_DETAIL}/{slug}/", diff)
        if status == 200:
            print(f"updated  {slug}: {change}")
            updated += 1
        else:
            print(f"FAILED   {slug} ({status}): {short(resp)}")
            failed += 1
        time.sleep(0.3)

    verb = "to update" if not APPLY else "updated"
    print(f"\n--- {verb}={updated} already-ok={ok} failed={failed} "
          f"({len(comps)} components)")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
