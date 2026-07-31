#!/usr/bin/env python3
"""Create missing Weblate components for the bundled plugin language files.

luadch ships one monolingual-JSON language file per plugin per language at
``scripts/lang/<lng>/<name>.json`` (see docs/TRANSLATING.md). Weblate needs one
*component* per plugin. The "Component discovery" add-on that would auto-create
them is not available on our instance, so this script does it over the REST API
instead: it creates a component for every ``scripts/lang/en/<name>.json`` that
does not have one yet, each LINKED to the Core component's repository
(``weblate://<project>/<core-slug>``) so nothing re-clones and they share the
push branch + credentials.

It is **idempotent and non-destructive**: it only ever POSTs new components and
skips ones that already exist; it never modifies or deletes anything. So it is
safe to run repeatedly - on CI when a new plugin lang file lands, or by hand.

Environment:
  WEBLATE_URL        base URL, e.g. https://translate.dcvault.net   (required)
  WEBLATE_API_TOKEN  a Weblate API token (Settings -> API access)   (required)
  WEBLATE_PROJECT    project slug                    (default: luadch-ng)
  WEBLATE_CORE_SLUG  Core component slug for the weblate:// link.
                     Optional - auto-detected as the one component whose repo
                     is a real VCS URL (not a weblate:// link) when omitted.

Run from the repository root. Exit code 0 = all good, 1 = at least one failure.
"""

import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from glob import glob

URL = os.environ.get("WEBLATE_URL", "").rstrip("/")
TOKEN = os.environ.get("WEBLATE_API_TOKEN", "")
# `or "luadch-ng"` (not the .get default) so an env var set to the empty string
# - as GitHub Actions passes an unset `vars.WEBLATE_PROJECT` - still falls back
# to the real project slug on translate.dcvault.net.
PROJECT = os.environ.get("WEBLATE_PROJECT") or "luadch-ng"
CORE_SLUG = os.environ.get("WEBLATE_CORE_SLUG", "").strip()

if not URL or not TOKEN:
    sys.exit("error: WEBLATE_URL and WEBLATE_API_TOKEN must be set")

COMPONENTS = f"{URL}/api/projects/{PROJECT}/components/"


# A browser-like User-Agent. urllib's default ("Python-urllib/3.x") is an
# instant bot signal for a Cloudflare-fronted instance (translate.dcvault.net)
# and gets served the "Just a moment..." challenge instead of JSON. Overridable
# via WEBLATE_USER_AGENT for tuning without a code change.
USER_AGENT = os.environ.get(
    "WEBLATE_USER_AGENT",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36",
)


def api(method, url, data=None):
    """Return (status_code, parsed_or_text). Never raises on HTTP errors."""
    body = urllib.parse.urlencode(data).encode() if data else None
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", f"Token {TOKEN}")
    req.add_header("User-Agent", USER_AGENT)
    req.add_header("Accept", "application/json")
    if body:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            raw = r.read()
            return r.status, (json.loads(raw) if raw else None)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        return 0, str(e)


# 1. Enumerate existing components (paginated). Collect the ones backed by a
#    real VCS repo (not a weblate:// link) as Core candidates - normally exactly
#    one (the Core component); the per-plugin components all link via weblate://.
existing = set()
core_candidates = set()
nxt = COMPONENTS + "?page_size=100"
while nxt:
    status, page = api("GET", nxt)
    if status == 404:
        sys.exit(
            f"error: project '{PROJECT}' not found (404) - check the project slug "
            f"in the Weblate URL (/projects/<slug>/) and set WEBLATE_PROJECT"
        )
    if status != 200 or not isinstance(page, dict):
        sys.exit(f"error: listing components failed ({status}): {page}")
    for comp in page.get("results", []):
        existing.add(comp["slug"])
        repo = str(comp.get("repo", ""))
        if repo and not repo.startswith("weblate://"):
            core_candidates.add(comp["slug"])
    nxt = page.get("next")

# Resolve the Core component slug. An explicit override always wins; otherwise
# auto-detect, but FAIL LOUD on ambiguity rather than silently link the new
# plugin components to an arbitrary one.
core = CORE_SLUG
if not core:
    if len(core_candidates) == 1:
        core = next(iter(core_candidates))
    elif not core_candidates:
        sys.exit(
            "error: no Core component found (none has a real VCS repo) - create "
            "the Core component first, or set WEBLATE_CORE_SLUG"
        )
    else:
        sys.exit(
            "error: multiple candidate Core components "
            f"{sorted(core_candidates)} - set WEBLATE_CORE_SLUG to disambiguate"
        )

# 2. Enumerate the plugins from the repo checkout.
plugins = sorted(
    os.path.basename(p)[:-5] for p in glob("scripts/lang/en/*.json")
)
if not plugins:
    sys.exit("error: no scripts/lang/en/*.json found - run from the repo root")

# 3. Create the missing ones.
created = skipped = failed = 0
for name in plugins:
    # Skip-existing keys on the slug, and this script always creates with
    # slug == plugin filename; a component pre-created by hand with a divergent
    # slug would be re-POSTed here and 400 (loud, non-destructive), so keep the
    # convention: a plugin's component slug equals its lang-file basename.
    if name in existing:
        skipped += 1
        continue
    status, resp = api("POST", COMPONENTS, {
        "name": name,
        "slug": name,
        "file_format": "json",
        "repo": f"weblate://{PROJECT}/{core}",
        "filemask": f"scripts/lang/*/{name}.json",
        "template": f"scripts/lang/en/{name}.json",
        "new_base": f"scripts/lang/en/{name}.json",
        "source_language": "en",
        "new_lang": "add",
        "language_regex": r"^(?!en$).+$",
    })
    if status == 201:
        print(f"created  {name}")
        created += 1
    else:
        print(f"FAILED   {name} ({status}): {resp}")
        failed += 1
    time.sleep(0.3)

print(f"--- created={created} skipped={skipped} failed={failed} "
      f"(core={core}, {len(plugins)} plugins)")
sys.exit(1 if failed else 0)
