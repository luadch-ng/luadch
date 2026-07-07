#!/usr/bin/env python3
"""Static guard: every plugin in core/cfg_defaults.lua's `scripts` default
must be bundled in scripts/.

The hub falls back to this in-memory default cfg when cfg/cfg.tbl is missing
(a fresh or partially-seeded install - see docker/entrypoint.sh block 1d).
If the default lists a plugin that is not bundled, that boot path errors on
a missing file. That is exactly how cmd_pm2offliners slipped through: it was
migrated to the companion luadch-ng/scripts repo and removed from scripts/ +
examples/cfg/cfg.tbl, but the entry in the cfg_defaults scripts default was
missed - so a fresh install with no cfg.tbl logged a checkfile error.

The normal boot (with cfg/cfg.tbl present) loads examples/cfg's script list,
which the smoke harness already validates via test_no_script_errors; this
guard covers the OTHER path - the built-in fallback default.

Run: python tests/check_default_cfg_scripts.py
"""
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def main() -> int:
    path = os.path.join(ROOT, "core", "cfg_defaults.lua")
    with open(path, encoding="utf-8", errors="ignore") as fh:
        defaults = fh.read()

    m = re.search(r"\n    scripts = \{(.*?)\n    \},", defaults, re.S)
    if not m:
        print("FAIL: could not locate the `scripts` default block in cfg_defaults.lua")
        return 1

    # Strip Lua line-comments first so a commented-out `-- "foo.lua",` entry
    # is not counted; allow hyphens in names for future companion-repo files.
    block = re.sub(r"--[^\n]*", "", m.group(1))
    listed = re.findall(r'"([\w.\-]+\.lua)"', block)
    bundled = {
        f for f in os.listdir(os.path.join(ROOT, "scripts")) if f.endswith(".lua")
    }
    missing = [s for s in listed if s not in bundled]

    if missing:
        print("FAIL: cfg_defaults.lua `scripts` default lists plugins not bundled in scripts/:")
        for s in missing:
            print(f"   - {s}")
        print("Fix: bundle the plugin, or remove it from the scripts default")
        print("     (companion-repo plugins must NOT be in the default scripts list).")
        return 1

    print(f"OK: all {len(listed)} scripts in the cfg_defaults default are bundled")
    return 0


if __name__ == "__main__":
    sys.exit(main())
