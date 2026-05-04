# Phase 7a - Security audit findings

> Working agreement: see [`CLAUDE.md`](../../CLAUDE.md) §1.
> Phase 7 scope: see [`CLAUDE.md`](../../CLAUDE.md) §5.

**Status:** read-only audit pass complete
**Started:** 2026-05-04
**Scope:** Complete security audit of the modernised Phase-6 codebase. No code
changed in 7a. Each finding is filed as a GitHub issue and triaged into a
later sub-phase (7b+) by severity.

---

## 1. Methodology

Every surface listed in [`CLAUDE.md`](../../CLAUDE.md) §5 Phase 7 was reviewed
by reading the relevant Lua / C / C++ source in full and grepping the wider
repo for callers and divergent code paths. Three independent surfaces (C/C++,
ADC parser + TLS, dependency CVEs) were audited in parallel by sub-agents to
reduce single-reader bias; their findings were merged with the maintainer's
direct read of the file-I/O, auth, secret-handling, and sandbox surfaces.

### Threat model

The hub runs untrusted clients on the public internet. The plugin scripts
under [`scripts/`](../../scripts) are admin-authored and trusted (this is the
documented contract of the plugin loader at
[`core/scripts.lua:168-222`](../../core/scripts.lua)). Configuration files
([`cfg/cfg.tbl`](), [`cfg/user.tbl`](), [`cfg/lang/*.lng`]()) are written by
the hub itself or the admin; an attacker who can write these files already
has equivalent-or-greater privilege than the hub, but - as the loader is
`loadfile()`-based - any *partial* write primitive (FTP, share, plugin bug,
backup-restore) gets upgraded to full RCE. Findings F-FIO-1 and F-AUTH-1 are
shaped by this threat model.

### Severity scale

| Tag | Meaning |
|---|---|
| **critical** | RCE without prior privilege, or trivially exploitable on a default install |
| **high** | RCE with limited prior privilege, auth bypass, or stable DoS against a default install |
| **medium** | Account-DoS, partial info disclosure, or exploit conditional on a non-default config |
| **low** | Defence-in-depth gap, or exploit requires improbable preconditions |
| **info** | No exploit; documents an assumption / portability landmine / hygiene item |

### Severity rollup

| Severity | Count |
|---|---|
| critical | 1 |
| high | 3 |
| medium | 9 |
| low | 7 |
| info | 4 |

---

## 2. Findings

### Critical

#### F-FIO-1 ([#51](https://github.com/Aybook/luadch/issues/51)) - `util.loadtable()` executes arbitrary Lua from any tampered `.tbl` file
- **Files:** [`core/util.lua:276-291`](../../core/util.lua), called from
  [`core/cfg.lua:610,624,644`](../../core/cfg.lua),
  [`core/cfg_users.lua:51,67,73`](../../core/cfg_users.lua),
  [`core/cfg_lang.lua:56`](../../core/cfg_lang.lua), and 20+ scripts that
  persist their state via the same helper.
- **Evidence:** `loadtable()` calls `loadfile(path)` then runs the chunk
  with the hub's full `_ENV` (full `os`, `io`, `debug`, `package`). The save
  side (`util.savetable`) emits well-formed Lua via `%q` formatting, so
  legitimate writes cannot inject - the risk is exclusively *file-tamper*.
- **Why it matters:** Any path that lets an attacker partially write to
  [`cfg/user.tbl`](), [`cfg/cfg.tbl`](), [`cfg/lang/*.lng`](), or any of the
  per-script `.tbl` files (bans, sessions, hubstats, blacklist, ...) becomes
  full RCE on the hub host. The blast radius is the entire `cfg/` subtree.
- **Fix direction:** Migrate `loadtable()` / `savetable()` to a non-executable
  serialisation format (JSON via `dkjson`, or a hand-rolled
  table-literal parser that does NOT invoke `loadfile`). Migration is
  mechanical but touches 50+ call sites - candidate for a dedicated 7b sub-phase.

### High

#### F-AUTH-1 ([#52](https://github.com/Aybook/luadch/issues/52)) - Registered-user passwords stored in plaintext at rest
- **Files:** [`core/hub_user_object.lua:397-440`](../../core/hub_user_object.lua),
  [`core/cfg_users.lua`](../../core/cfg_users.lua),
  [`core/hub_dispatch.lua:354-389`](../../core/hub_dispatch.lua) (HPAS handler).
- **Evidence:** `profile.password` is the cleartext password. The HPAS
  exchange computes `Tiger(password || salt)` server-side at challenge time
  - this is the ADC-protocol-mandated mechanism (see ADC §5.3.2). Without
  the cleartext, the salted-Tiger challenge cannot be answered.
- **Why it matters:** Any leak of [`cfg/user.tbl`]() (filesystem read,
  backup theft, misconfigured share, ransomware exfiltration) directly
  yields plaintext credentials for every registered user.
- **Fix direction:** Cannot be cleanly fixed without an ADC protocol
  extension. Mitigation candidates: enforce restrictive file permissions
  (see F-SEC-1), document the at-rest risk for operators, and consider an
  optional HMAC-with-machine-key wrapper that turns the file into "decrypts
  only on this host". Long-term: track an ADC extension that supports
  hashed-at-rest credentials.

#### F-AUTH-2 ([#53](https://github.com/Aybook/luadch/issues/53)) - `math.random()`-based password salt; reseeded with second-resolution time by `util.generatepass`
- **Files:** [`core/adc.lua:545-553`](../../core/adc.lua) (`adclib.createsalt`),
  [`core/util.lua:447-467`](../../core/util.lua) (`generatepass`).
- **Evidence:** `createsalt` builds salts via `math.random()` of base32 chars.
  `util.generatepass()` calls `math.randomseed(os.time())` every invocation,
  *overriding* the secure default seed Lua 5.4 generates at boot. Subsequent
  calls to `math.random()` (every salt for every login challenge) draw from
  the now-second-precision seed.
- **Why it matters:** An attacker who can guess approximately when an admin
  generated a password (e.g. "shortly after I made my account") gets a tiny
  search space of `os.time()` values to brute-force the password. Worse: from
  the moment `generatepass` runs, the PRNG state is recoverable from any
  observed salt, letting an attacker pre-compute `Tiger(candidate || future_salt)`
  for opportunistic brute force across many login attempts.
- **Fix direction:** Use a CSPRNG. Either (a) read from
  `/dev/urandom` / `BCryptGenRandom` via a small C shim, or (b) use OpenSSL's
  `RAND_bytes` (already linked via LuaSec). Remove the
  `math.randomseed(os.time())` reseed entirely - Lua 5.4 already seeds
  weakly-randomly at boot.

#### F-C-1 ([#54](https://github.com/Aybook/luadch/issues/54)) - Variable-length stack array sized by attacker-controlled input
- **Files:** [`adclib/adclib.cpp:157-158`](../../adclib/adclib.cpp) (`hash_pas`),
  [`adclib/adclib.cpp:176-177`](../../adclib/adclib.cpp) (`hash_pas_oldschool`).
- **Evidence:** `size_t saltBytes = salt.size()*5/8; unsigned char chunk[saltBytes];`
  - VLA whose size is derived from the Lua-side salt argument. VLAs are also
  non-standard C++ (GCC extension; MSVC rejects).
- **Why it matters:** A multi-MB salt blows the stack frame -> SIGSEGV / hub
  crash. While the legitimate ADC salt is bounded (10 base32 chars by default),
  the C function does not enforce this; any plugin or future call site that
  forwards untrusted input becomes a one-byte stack-DoS.
- **Fix direction:** Validate `salt.size()` against a small constant (32 bytes
  is more than enough), then use a fixed-size `unsigned char chunk[64]` or
  `std::vector<unsigned char>`.

### Medium

#### F-AUTH-3 ([#56](https://github.com/Aybook/luadch/issues/56)) - Bad-password lockout is per-account, not per-IP
- **Files:** [`core/hub_dispatch.lua:330-373`](../../core/hub_dispatch.lua).
- **Evidence:** `profile.badpassword` increments per-account on bad
  password; lockout window is bypassed once `bad_pass_timeout` elapses
  (no permanent block).
- **Why it matters:** (a) attacker-controlled account-DoS - by deliberately
  failing N times, an attacker locks out a legitimate user; (b) no defence
  against parallel cross-account fishing - attacker guesses one common
  password against many accounts simultaneously, since the throttle is
  per-account not per-source-IP.
- **Fix direction:** Add per-IP bad-attempt counter alongside the per-account
  one; rate-limit *connections* from a single IP regardless of which account
  they target.

#### F-PRS-1 ([#57](https://github.com/Aybook/luadch/issues/57)) - `_regex.nowhitespace` matches literal `\n` / `\s` escape sequences, not raw control bytes
- **Files:** [`core/adc.lua:220-222`](../../core/adc.lua).
- **Evidence:** `not (string_find(str, "\\n") or string_find(str, "\\s"))` -
  the pattern `"\\n"` is the *two-byte* sequence backslash-n, not a real `\n`
  byte (`"\n"`). A raw `\r`, vertical-tab, or other ADC-forbidden control
  byte slips past.
- **Why it matters:** Combined with the sibling token splitter
  `string_gsub(data, "([^ ]+)", tokenize)` which only splits on space, an
  attacker can shape `INF NI<CR>...` and similar fields with embedded
  control bytes that are then forwarded to other clients, log lines, and
  downstream consumers.
- **Fix direction:** Use `string_find(str, "[%s]")` (or explicit
  `[\r\n\t\v\f]`) on the raw string. Apply the same rule to every
  user-controlled named-parameter field in `_regex`.

#### F-PRS-2 ([#57](https://github.com/Aybook/luadch/issues/57)) - `_regex.default` is a no-op validator on many INF/MSG fields
- **Files:** [`core/adc.lua:214`](../../core/adc.lua) (definition - returns
  `true` unconditionally), referenced by INF.NI, INF.DE, INF.EM, INF.AP,
  INF.VE, INF.KP and the positional MSG body across the `_adccmds` table.
- **Evidence:** Every field that points at `_regex.default` accepts arbitrary
  bytes after the early UTF-8 / no-`<space>` token check.
- **Why it matters:** No injection of CR/NL/NUL is currently exploitable
  because the BMSG / INF body is forwarded as-is to other clients - the
  protocol is line-based at the parser layer but ADC framing escapes special
  bytes via `\s`, `\n`, `\\`, leaving raw `\r` / NUL as legal-but-dangerous
  payload in user-controlled fields. Defence-in-depth gap that pairs with
  F-PRS-1.
- **Fix direction:** Replace `_regex.default` with a real
  "no `\r` / `\n` / NUL / control-char" validator. Audit every `_adccmds`
  table entry that reaches user-broadcast paths.

#### F-NET-1 ([#56](https://github.com/Aybook/luadch/issues/56)) - No per-IP / per-rate connection limit
- **Files:** [`core/server.lua:329-355`](../../core/server.lua),
  [`core/hub.lua:1437,1447`](../../core/hub.lua) (`maxconnections = 10000`).
- **Evidence:** Only a global per-listener cap (10 000). No per-source-IP
  limit, no accept-rate ceiling.
- **Why it matters:** A single attacker IP can open 10 000 sockets,
  exhausting hub FDs and slot tables. Combined with F-NET-2, slowloris-style
  attacks are cheap.
- **Fix direction:** Per-IP connection cap (cfg-tunable, default 8) and an
  accept-rate ceiling enforced in the `wrapserver` / `accept` path.

#### F-NET-2 ([#56](https://github.com/Aybook/luadch/issues/56)) - TLS handshake has no time deadline
- **Files:** [`core/server.lua:609-639`](../../core/server.lua).
- **Evidence:** Up to 20 yields on `wantread` / `wantwrite` with no
  wall-clock cap. `_max_idle_time = 30 * 60` only triggers via
  `_activitytimes` / `_writetimes`, which are not stamped during
  handshake; a connection sitting in handshake limbo holds the FD for the
  full 30-minute idle window.
- **Why it matters:** Slowloris-style attack against TLS - open many
  connections, send 1 byte every few seconds during handshake, exhaust
  FDs. Cheap to weaponise, especially without F-NET-1.
- **Fix direction:** Stamp `_activitytimes[handler] = _currenttime` at
  handshake start; add a dedicated `_handshake_timeout` (10 s default) and
  force-close on expiry.

#### F-C-3 ([#55](https://github.com/Aybook/luadch/issues/55)) - `luaL_checkstring` used for binary-input Lua strings
- **Files:** [`adclib/adclib.cpp:140`](../../adclib/adclib.cpp) (`hash_pid`),
  `:155-156` (`hash_pas`), `:174-175` (`hash_pas_oldschool`).
- **Evidence:** `luaL_checkstring` returns `const char*` and stops at the
  first embedded `\0`. Lua strings are binary-safe and may contain NULs.
- **Why it matters:** Truncated input silently produces a different hash. A
  password buffer with a stray NUL silently authenticates against a
  shorter credential than intended; corner case but non-zero.
- **Fix direction:** Replace every `luaL_checkstring` with
  `luaL_checklstring` and pass the explicit length to `update()`.

#### F-C-2 ([#58](https://github.com/Aybook/luadch/issues/58)) - Operator-precedence latent bug in tiger position mask
- **Files:** [`adclib/tiger.cpp:105`](../../adclib/tiger.cpp), `:134`.
- **Evidence:** `pos & BLOCK_SIZE - 1`. Operator precedence makes `-` bind
  tighter than `&`, which - by chance - gives the *intended* `pos & (BLOCK_SIZE - 1)`.
- **Why it matters:** A future maintainer reading the code as
  "pos & BLOCK_SIZE then minus one" who "fixes" the parentheses inverts
  the mask, silently corrupting every hash -> auth-bypass risk.
- **Fix direction:** Add the parentheses now: `pos & (BLOCK_SIZE - 1)`.
  Trivial.

#### F-DEP-2 ([#58](https://github.com/Aybook/luadch/issues/58)) - LuaSec 1.3.2 still uses pre-OpenSSL-3 deprecated APIs (issue [#3](https://github.com/Aybook/luadch/issues/3))
- **Files:** [`luasec/src/ssl.c:1050-1055`](../../luasec/src/ssl.c),
  [`luasec/src/context.c:226,554`](../../luasec/src/context.c).
- **Evidence:** `SSL_library_init`, `OpenSSL_add_all_algorithms`,
  `SSL_load_error_strings`, `PEM_read_bio_DHparams`,
  `SSL_CTX_set_tmp_dh_callback` - all `OPENSSL_NO_DEPRECATED_3_0`-tagged.
- **Why it matters:** The deprecation warnings already noted in #3 still
  fire; functionally OK because OpenSSL 3 auto-inits and the deprecated DH
  path still works, but the surface is moving and a future OpenSSL bump
  removes these symbols entirely.
- **Fix direction:** Already classified `upstream-blocked` /  `wontfix` in
  Phase 4. Re-evaluate if upstream cuts LuaSec 1.4.x or assess
  `lua-openssl` as a replacement (network-stack-renewal scope, deferred).

#### F-SEC-1 ([#55](https://github.com/Aybook/luadch/issues/55)) - No filesystem-permission policy on `cfg/user.tbl`, `cfg/cfg.tbl`, `certs/serverkey.pem`
- **Files:** [`core/util.lua:294-306`](../../core/util.lua) (`savetable`),
  [`core/cfg_users.lua`](../../core/cfg_users.lua),
  [`examples/certs/make_cert.sh`](../../examples/certs/make_cert.sh).
- **Evidence:** `io.open(path, "w+")` honours the process umask; no
  `chmod` is applied after creation. `make_cert.sh` does not set 0600 on
  the generated `serverkey.pem`.
- **Why it matters:** On Linux with a default umask of 022, secret files
  end up world-readable. On Windows, they inherit the parent directory's
  ACL.
- **Fix direction:** After every secret-file create, `os.execute("chmod 600 ...")`
  on POSIX and a small C-API call on Windows (or document a one-time
  install-step). `make_cert.sh` should `chmod 600` the key. Trivial fix.

### Low

#### F-PRS-3 ([#57](https://github.com/Aybook/luadch/issues/57)) - UTF-8 check commented out at `parse()` entry
- **Files:** [`core/adc.lua:738`](../../core/adc.lua).
- **Evidence:** `--types_utf8( data )`. Mitigated by `core/hub.lua:1222`
  gating `adclib_isutf8` before calling `adc_parse`, but defence-in-depth is
  missing.
- **Fix direction:** Re-enable inside `parse()`.

#### F-PRS-4 ([#57](https://github.com/Aybook/luadch/issues/57)) - `parse()` uses module-global `_buffer` / `_clone` - non-reentrant
- **Files:** [`core/adc.lua:159,594-597,869`](../../core/adc.lua).
- **Evidence:** `_buffer` is appended-only; only `_eol` is reset. A future
  `coroutine.yield` inside `parse()` (or recursive call from a script)
  silently corrupts state.
- **Fix direction:** Make `_buffer`, `_eol`, `_clone` locals inside
  `parse()`, or explicitly truncate at the start of every call.

#### F-PRS-5 ([#57](https://github.com/Aybook/luadch/issues/57)) - No upper bound on parsed message size at the parser layer
- **Files:** [`core/adc.lua:746-750`](../../core/adc.lua).
- **Evidence:** Only `_eol < 2` lower bound; no upper. Mitigated by
  [`core/server.lua:184`](../../core/server.lua) `_maxreadlen = 1 MiB`.
- **Fix direction:** Cap individual ADC commands at 64 KiB and disconnect
  on excess.

#### F-C-4 ([#58](https://github.com/Aybook/luadch/issues/58)) - `atexit` accumulation on `+reload`
- **Files:** [`hub/hub.c:175-204`](../../hub/hub.c).
- **Evidence:** Every restart pushes another `run_lua` onto the atexit
  stack. POSIX guarantees only 32 registrations; further `atexit()` calls
  silently fail (return value unchecked).
- **Fix direction:** Check `atexit()` return value; consider an explicit
  re-init loop instead of `atexit + exit`.

#### F-DEP-1 ([#55](https://github.com/Aybook/luadch/issues/55)) - Lua 5.4.7 lags 5.4.8
- **Files:** [`lua/src/lua.h:21`](../../lua/src/lua.h).
- **Evidence:** Bundled 5.4.7; upstream 5.4.8 (2025-06-04). Eight bugs
  fixed including a code-generation flaw and an emergency-GC use-after-free
  - none CVE-flagged.
- **Fix direction:** Bump to 5.4.8. Patch releases are ABI-stable; re-run
  the Phase 6 smoke harness to verify.

#### F-DEP-3 ([#58](https://github.com/Aybook/luadch/issues/58)) - basexx vendored without provenance metadata
- **Files:** [`basexx/basexx.lua`](../../basexx/basexx.lua).
- **Evidence:** No `_VERSION`, no commit SHA, no module header. Upstream
  `aiq/basexx` last tagged v0.4.1 (2019-04-23); repo essentially abandoned.
- **Fix direction:** Add a one-line header capturing upstream commit SHA +
  retrieval date so future audits can diff without spelunking.

#### F-DEP-4 ([#58](https://github.com/Aybook/luadch/issues/58)) - OpenSSL DLL bundling is install-time, not version-pinned at build
- **Files:** [`CMakeLists.txt:52,99`](../../CMakeLists.txt).
- **Evidence:** Linux `find_package(OpenSSL REQUIRED)` has no version
  constraint; a maintainer could ship against EOL'd OpenSSL 1.1.1 and the
  build succeeds silently.
- **Fix direction:** `find_package(OpenSSL 3.0 REQUIRED)`.

### Info

#### F-SAND-1 ([#58](https://github.com/Aybook/luadch/issues/58)) - Plugin sandbox is privileged by design
- **Files:** [`core/scripts.lua:168-222`](../../core/scripts.lua).
- **Evidence:** Each plugin's `_ENV` is built by copying every entry of
  `_G` into a fresh table - so plugins have full access to `os`, `io`,
  `debug`, `package`. `cfg.no_global_scripting` only adds an
  error-on-undeclared-global metatable, it does NOT restrict library
  surface.
- **Why it's `info`:** Plugins are admin-authored per the documented
  contract. The "sandbox" is namespace-isolation, not capability-confinement.
- **Fix direction:** None - document the trust contract explicitly in a new
  `docs/SECURITY.md` so operators know they must vet every plugin they
  install.

#### F-PRS-6 ([#58](https://github.com/Aybook/luadch/issues/58)) - Unknown short named parameters forwarded verbatim
- **Files:** [`core/adc.lua:842-866`](../../core/adc.lua).
- **Evidence:** When `npregex` is nil and `_clone[name]` is clean, the
  parser copies the unknown 2-letter parameter into the outgoing command.
- **Why it's `info`:** Forwards-compat with future ADC extensions; not
  itself an exploit. Pairs with F-PRS-2 as the corridor a future
  protocol-confusion bug would use.
- **Fix direction:** Either drop unknown named params on B/F broadcast
  paths, or validate against a safe-charset.

#### F-DEP-5 - LuaSec 1.3.2 / LuaSocket 3.1.0 / Lua 5.4.7 have no public CVEs (no issue, audit-only)
- **Files:** repo-wide.
- **Evidence:** GitHub Advisory DB, NVD, CVE Mitre return no advisories
  for any of the three bundled deps at their current versions.
- **Fix direction:** Set up CVE-tracking process (see §4 below).

#### F-C-5 ([#58](https://github.com/Aybook/luadch/issues/58)) - Tiger strict-aliasing / endian assumptions
- **Files:** [`adclib/tiger.cpp:117,123,143,151,152`](../../adclib/tiger.cpp).
- **Evidence:** `(unsigned long long *)tmp` casts violate strict aliasing;
  finalize assumes little-endian. Phase-5 verified ARM-LE; big-endian and
  strict-alignment ARMv7 would silently produce a wrong hash.
- **Fix direction:** `memcpy` into aligned local; byte-wise serialise the
  length. Portability landmine, not exploitable on x86 / aarch64-LE.

---

## 3. What 7a explicitly did NOT find

Recorded as negative findings so a future auditor does not re-derive them:

- **No format-string bugs** in `hub/hub.c` (Finding 10 in the C audit
  confirmed `%s` is a literal).
- **No `strcpy` / `strcat` / `sprintf` overflows** in `adclib/*.cpp` -
  `std::string` is used throughout.
- **No `register`-keyword leftovers** in `adclib/` (Phase 2 cleanup
  verified complete).
- **No password / salt / hash material logged** anywhere in `core/` (grep
  for `out.put`, `out.error`, `hub.debug` returned nothing in
  password-touching code paths). Login failures log the *reason string*
  to `onFailedAuth`, not the candidate password.
- **No peer-cert verify accidentally enabled** in
  [`core/server.lua`](../../core/server.lua) - LuaSec defaults are correct
  for the server-side ADC role.
- **TLS protocol set to "tlsv1_3"** in default cfg with `"HIGH"` cipher
  list and `no_sslv2` / `no_sslv3` options - reasonable defaults.

---

## 4. CVE-tracking process (recommendation)

Concrete steps the maintainer should adopt going forward:

1. Watch the GitHub Releases / Security Advisories of each upstream:
   - [`lunarmodules/luasec`](https://github.com/lunarmodules/luasec)
   - [`lunarmodules/luasocket`](https://github.com/lunarmodules/luasocket)
   - [`aiq/basexx`](https://github.com/aiq/basexx)
   - [`openssl/openssl`](https://github.com/openssl/openssl)
   - Lua: subscribe to the [`lua-l` mailing list](https://www.lua.org/lua-l.html)
2. Add a quarterly checklist entry to the next phase journal: run three
   queries against [`osv.dev`](https://osv.dev) and the GitHub Advisory
   Database for the four ecosystems above.
3. Record bundled SHA / version of every dep in
   [`docs/BUILDING.md`](../BUILDING.md) so audits compare to a written
   truth, not to greps.

---

## 5. Phase 7b+ recommended ordering

By severity and effort:

| Sub-phase | Findings | Effort | Notes |
|---|---|---|---|
| 7b | F-AUTH-2, F-C-1, F-C-3, F-SEC-1, F-DEP-1 | small | High-severity quick wins; 5 small PRs. F-AUTH-2 is the most consequential (CSPRNG for salts). |
| 7c | F-AUTH-3, F-NET-1, F-NET-2 | medium | DoS hardening - per-IP caps, handshake deadline, throttle. |
| 7d | F-PRS-1, F-PRS-2, F-PRS-3, F-PRS-4, F-PRS-5 | medium | ADC parser hardening - validators + reentrancy. |
| 7e | F-FIO-1 | large | The big one. `loadtable` migration touches 50+ call sites; needs its own design doc + migration shim. |
| 7f | F-AUTH-1 | n/a | Document at-rest risk in [`docs/SECURITY.md`](../SECURITY.md); long-term action depends on ADC-protocol movement. |
| - | F-C-2, F-C-4, F-C-5, F-DEP-2, F-DEP-3, F-DEP-4, F-PRS-6, F-SAND-1 | small/info | Hygiene + documentation; can be batched into a single 7g PR. |

**Review gate exit criteria for Phase 7:** every finding in this document
is either fixed or has a tracking issue with a documented disposition
(`fixed in 7X`, `wontfix-with-rationale`, `upstream-blocked`, or
`deferred-to-phase-8`). No critical or high-severity finding remains
unaddressed.
