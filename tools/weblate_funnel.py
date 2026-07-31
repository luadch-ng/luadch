#!/usr/bin/env python3
"""Funnel real Weblate translations from the `weblate` staging branch into a dev checkout.

Weblate creates a target language file the moment a language is *added*, even
with zero translated strings, and pushes it to the `weblate` branch. It also
reformats files it touches (4-space indent) without changing any value. Merging
`weblate` -> `dev` wholesale would therefore drag in empty language skeletons and
pure-reformatting churn that carry no translation - exactly the clutter #553 hit.

This script filters that: it copies a language file from `weblate` into the
working tree (a `dev` checkout) ONLY when the file's set of non-empty translated
values actually differs from what `dev` already has. So:

  - a 0%-translated language (all values "") -> no non-empty leaves -> skipped;
  - a file Weblate only reformatted (same values) -> same leaves -> skipped;
  - a file with a real new/changed/removed translation -> included (Weblate's
    full file, preserving its format and its empty keys for untranslated
    strings, so Weblate's next sync sees no divergence).

Weblate is the source of truth for translations: a file is imported whenever its
non-empty content differs in EITHER direction, so a string removed/emptied in
Weblate overwrites dev's version. Do not hand-edit translations in `dev` - they
will be clobbered on the next funnel; translate in Weblate instead. The
maintainer PR review is the backstop against an accidental mass-empty.

Run from the repository root, on a checkout of the target branch (dev), with the
source branch fetched (default `origin/weblate`). It only WRITES files into the
working tree and prints a summary; it does not commit, push, or touch git refs.

Outputs (for the workflow):
  - stdout: a human summary + machine lines `FUNNEL_LANGS=<csv>` and
    `FUNNEL_CHANGED=<0|1>`;
  - if $GITHUB_OUTPUT is set: `langs=<csv>` and `changed=<0|1>` appended.

Exit code is always 0 unless something is genuinely broken (bad git ref, unreadable
source); "nothing to funnel" is a normal, successful outcome (changed=0).
"""

import json
import os
import re
import subprocess
import sys

SOURCE_REF = os.environ.get("WEBLATE_FUNNEL_SOURCE", "origin/weblate")

# Language subdir codes we accept (de, en, pt_BR, zh_Hans, ...). Anything else
# is skipped: it keeps a malformed/hostile path (shell metacharacters, traversal)
# out of the git commit / PR title even though git already quotes such paths.
LANG_CODE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]*$")


def git(*args):
    return subprocess.run(
        ["git", *args], capture_output=True, text=True, encoding="utf-8"
    )


def source_files():
    """Language JSON files on the source ref, excluding the English source."""
    r = git("ls-tree", "-r", "--name-only", SOURCE_REF)
    if r.returncode != 0:
        sys.exit(f"error: cannot list {SOURCE_REF}: {r.stderr.strip()}")
    out = []
    for f in r.stdout.splitlines():
        if not f.endswith(".json"):
            continue
        if f.startswith("lang/"):
            lng = f.split("/")[1]
        elif f.startswith("scripts/lang/"):
            lng = f.split("/")[2]
        else:
            continue
        if lng == "en" or not LANG_CODE_RE.match(lng):
            continue
        out.append((lng, f))
    return out


def source_bytes(path):
    """Raw bytes of the file on the source ref (byte-exact: no newline rewrite).

    Reading text would apply universal-newline translation; writing the raw
    bytes keeps a file identical to Weblate's so the funnel does not perpetually
    re-import it over a CRLF/LF difference.
    """
    r = subprocess.run(["git", "show", f"{SOURCE_REF}:{path}"], capture_output=True)
    return r.stdout if r.returncode == 0 else None


def nonempty_leaves(obj, prefix=""):
    """Flatten to {path: value} for non-empty string leaves only.

    Empty strings are Weblate's marker for an untranslated key; ignoring them
    (and comparing only the real content) is what makes formatting-only and
    empty-language diffs collapse to "no change", mirroring the runtime's
    checklanguage which drops empty values.
    """
    leaves = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            leaves.update(nonempty_leaves(v, f"{prefix}.{k}"))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            leaves.update(nonempty_leaves(v, f"{prefix}[{i}]"))
    elif isinstance(obj, str):
        if obj.strip() != "":
            leaves[prefix] = obj
    return leaves


def decode(text):
    if text is None:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def main():
    included = []          # (lng, path)
    langs = set()          # languages with >=1 included file
    skipped_empty = set()  # languages seen but with no meaningful content
    malformed = []         # source files that would not decode

    for lng, path in source_files():
        src_raw = source_bytes(path)
        src = decode(src_raw.decode("utf-8", "replace")) if src_raw is not None else None
        if src is None:
            malformed.append(path)
            continue
        # dev's current version is the working-tree file (checkout of the target).
        dev = None
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as fh:
                dev = decode(fh.read())
        if nonempty_leaves(src) == nonempty_leaves(dev or {}):
            skipped_empty.add(lng)
            continue
        # Real translation content differs -> write the source's raw bytes as-is
        # (byte-exact: preserves Weblate's format, its empty keys for untranslated
        # strings, and its exact line endings so the funnel does not re-import it).
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as fh:
            fh.write(src_raw)
        included.append((lng, path))
        langs.add(lng)

    # A language counts as "skipped/empty" only if it contributed no file.
    skipped_empty -= langs

    langs_csv = ",".join(sorted(langs))
    changed = 1 if included else 0

    print(f"source ref: {SOURCE_REF}")
    print(f"included files: {len(included)}")
    for lng in sorted(langs):
        n = sum(1 for l, _ in included if l == lng)
        print(f"  + {lng}: {n} file(s) with real translations")
    if skipped_empty:
        print(f"skipped (no translated content / formatting-only): "
              f"{', '.join(sorted(skipped_empty))}")
    if malformed:
        print(f"WARNING: {len(malformed)} source file(s) did not decode and were "
              f"skipped: {', '.join(malformed[:10])}"
              + (" ..." if len(malformed) > 10 else ""))
    print(f"FUNNEL_LANGS={langs_csv}")
    print(f"FUNNEL_CHANGED={changed}")

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"langs={langs_csv}\n")
            fh.write(f"changed={changed}\n")


if __name__ == "__main__":
    main()
