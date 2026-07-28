# res/ - Windows executable resources

`res.rc` is the Windows VERSIONINFO + icon resource. windres compiles it and
the linker embeds it into `Luadch.exe` (wired in `hub/CMakeLists.txt`, WIN32
only). Its strings are what Explorer's Properties dialog and the Windows
Firewall prompt show as the app name (`FileDescription`), publisher
(`CompanyName`), and version.

Keep `FILEVERSION` / `PRODUCTVERSION` in sync with `core/const.lua` `VERSION`
(they drifted to 2,0,0,0 once while the build was already 3.2.x). The
`LegalCopyright` here reads "blastbeat, pulsar and Luadch-NG contributors" and
is intentionally worded differently from `core/const.lua` `COPYRIGHT` (original
authors only) - the Windows metadata credits the fork, the runtime constant
keeps the upstream attribution.

`luadch.ico` is generated from `luadch-ng.png` (the project logo, 500x500 RGBA)
at sizes 16/24/32/48/64/128/256. To regenerate after the logo changes, run this
from the repo root in a POSIX shell (Git Bash / WSL / the CI shell; needs
Pillow):

    python - <<'PY'
    from PIL import Image
    s = Image.open("res/luadch-ng.png").convert("RGBA")
    sizes = [16, 24, 32, 48, 64, 128, 256]
    f = [s.resize((n, n), Image.LANCZOS) for n in sorted(sizes, reverse=True)]
    f[0].save("res/luadch.ico", format="ICO",
              sizes=[(n, n) for n in sizes], append_images=f[1:])
    PY
