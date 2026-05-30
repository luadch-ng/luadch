--[[

    hbri.lua - HBRI (Hub-Bridged Reverse Initiation), #214.

    Verifies a dual-stack client's SECONDARY IP family over a
    second-family side-channel TCP connection, so the hub can safely
    broadcast it. Without HBRI the secondary family is stripped before
    broadcast (#214 Gap 1, core/hub_dispatch.lua) because the hub has
    no socket on the other family through which to authenticate the
    claimed address - broadcasting an unverified secondary is a DC++
    DDoS-amplification vector.

    Login-time flow (client main connection on family X, secondary Y):

      1. Client advertises ADHBRI in HSUP and a secondary IY in BINF.
         core/hub_dispatch.lua captures the claim (user._hbri_claim)
         BEFORE Gap 1 strips it. IY may be a concrete address OR the
         spec placeholder (I6:: / I40.0.0.0, the common auto-detect
         case) - the placeholder means "discover my address from the
         side-channel" (#291).
      2. After login (HPAS accepted), hub.lua's login() calls
         initiate(): mint a CSPRNG token, send the client an ITCP
         frame pointing at the hub's family-Y listener + token, move
         the user to the "hbri" state and DELAY entry into NORMAL.
      3. Client opens a SECOND TCP connection to the hub on family Y
         and sends `HTCP IY<addr> [UY<udp>] TO<token>`. That fresh
         connection is a transient "protocol"-state user; its first
         frame (HTCP, not HSUP) is routed to validate() by the
         _protocol.HTCP handler in core/hub_dispatch.lua.
      4. validate() checks: token known, validation-socket family ==
         the expected secondary family (and != the main family), and
         - for a CONCRETE claim - that the claimed address == the
         validation-socket TCP source. A placeholder claim skips that
         cross-check (#291 discovery). On success the secondary is
         committed as the AUTHENTICATED socket source (getpeername,
         never a client-stated value) and the user enters NORMAL (now
         broadcasting the validated secondary). On any failure - or a
         timeout swept by sweep() on the ~1s hub timer - the user
         enters NORMAL anyway with the secondary left stripped.

    Post-login flow (#286): a client already in NORMAL state that
    advertises a secondary in a later INF update is solicited the same
    way by postlogin_inf() (called from _normal.BINF before the #97 /
    #222 strip), but is NOT parked - it stays in NORMAL and a success
    broadcasts the validated INF directly (commit_and_complete). Three
    guards bound re-solicits: an in-flight token, an already-validated
    idempotence check, and a per-user cooldown. The unverified
    secondary is still stripped from the triggering broadcast, so an
    unproven address never reaches the wire.

    No core/server.lua change: the validation socket rides the normal
    accept path and is identified purely by its HTCP+token first frame -
    so it uses the advertised port's transport (plain OR TLS / autossl;
    a TLS side-channel works, the client matches its main connection's
    transport). HBRI needs a listener (plain or TLS) on both families.

    Token generation is OpenSSL-CSPRNG-backed (adclib.createsalt ->
    adclib.random_bytes), per the Yorhel security note that the token
    must not be guessable.

]]--

local use = use

local pairs    = use "pairs"
local tostring = use "tostring"
local ipairs   = use "ipairs"
local os       = use "os"
local adclib   = use "adclib"
local cfg      = use "cfg"

local cfg_get           = cfg.get
local adclib_createsalt = adclib.createsalt
local os_time           = os.time

-- // late-bound from hub.lua via bind(): the NORMAL-entry completion
-- // and the per-reload cfg caches.
local enter_normal           -- enter_normal(user): runs the deferred login
local sendtoall              -- sendtoall(adcstring): broadcast to all normal users (#286)
local _enabled               -- hbri_enabled cfg
local _timeout               -- hbri_timeout seconds (cfg-validated 1..60)
local _advertise = { I4 = "", I6 = "" }   -- hub public address per family
local _port      = { I4 = nil,  I6 = nil } -- plain listener port per family
local _dual_stack = false    -- a plain listener exists on BOTH families

-- // #301: i18n strings (ADC-escaped) for the validate()/sweep() ISTA
-- // reasons. Populated via set_i18n() at hub.lua loadlanguage time so
-- // a +reload picks up lang changes. Defaults preserve byte-identical
-- // behaviour if set_i18n() was never called (defensive only).
local _i18n_unknown_token    = "Unknown\\svalidation\\stoken"
local _i18n_wrong_protocol   = "Validation\\srequest\\son\\swrong\\sIP\\sprotocol"
local _i18n_address_mismatch = "Validation\\saddress\\smismatch"
local _i18n_succeed          = "Validation\\ssucceed"
local _i18n_timeout          = "Secondary\\saddress\\svalidation\\stimed\\sout"

-- // #286 post-login HBRI re-solicit cooldown (seconds). A logged-in
-- // client re-emits its full connectivity on every INF update (share
-- // change, NAT rebind, ...); idempotence (an already-validated
-- // secondary is skipped) covers the success case, and this bounds the
-- // FAILED case - a v6-broken dual-stack client - to one attempt per
-- // window per user instead of one per INF.
local _POSTLOGIN_COOLDOWN = 60

-- // token table: token -> {
-- //   user        = main user object,
-- //   family      = expected secondary family ("I4" | "I6"),
-- //   claimed_udp = secondary UDP port (string) or nil,
-- //   su_flags    = { secondary transport flags present in BINF SU },
-- //   deadline    = os.time() second past which the attempt times out,
-- // }
-- // The BINF-claimed secondary ADDRESS is deliberately NOT stored:
-- // validate() only ever commits the validation socket's getpeername
-- // (the authenticated source), never a client-stated address. Keeping
-- // it out of the table makes that invariant structural (#291).
local _tokens = { }

-- // The IP family of an address string: ADC IPv6 contains ":".
local function fam_of( ip )
    return ( ip and ip:find( ":", 1, true ) ) and "I6" or "I4"
end

local function other_fam( f )
    return ( f == "I4" ) and "I6" or "I4"
end

local function bind( deps )
    enter_normal = deps.enter_normal
    sendtoall    = deps.sendtoall
    _enabled     = deps.hbri_enabled and true or false
    _timeout     = deps.hbri_timeout
    _advertise.I4 = deps.hbri_advertise_v4 or ""
    _advertise.I6 = deps.hbri_advertise_v6 or ""
    _port.I4      = deps.hbri_port_v4
    _port.I6      = deps.hbri_port_v6
    _dual_stack   = deps.hbri_dual_stack and true or false
end

-- // #301: hub.lua's loadlanguage() forwards the relevant entries here so
-- // ISTA reasons emitted from validate()/sweep() are localised. Strings
-- // are already adclib_escape'd by the caller (they go straight onto the
-- // ADC frame). Called separately from bind() because hub.lua's init()
-- // does loadsettings()->bind() BEFORE loadlanguage().
local function set_i18n( strs )
    _i18n_unknown_token    = strs.hbri_unknown_token    or _i18n_unknown_token
    _i18n_wrong_protocol   = strs.hbri_wrong_protocol   or _i18n_wrong_protocol
    _i18n_address_mismatch = strs.hbri_address_mismatch or _i18n_address_mismatch
    _i18n_succeed          = strs.hbri_succeed          or _i18n_succeed
    _i18n_timeout          = strs.hbri_timeout          or _i18n_timeout
end

-- // Hub can drive HBRI at all: enabled, both families have a listener
-- // (plain OR TLS / autossl - the side-channel uses that port's
-- // transport), and both public advertise addresses are configured.
-- // (ADHBRI is advertised in SUP only when this holds, so a client
-- // never gets - or offers a secondary for - an ITCP it cannot reach.)
local function active( )
    return _enabled and _dual_stack
        and _advertise.I4 ~= "" and _advertise.I6 ~= ""
        and _port.I4 and _port.I6 and true or false
end

-- // This user should be HBRI-validated: the hub is HBRI-active, the
-- // client advertised ADHBRI, and the client claimed a secondary IP
-- // (captured pre-strip by the BINF handler) on the family opposite
-- // its main connection.
local function eligible( user )
    if not active( ) then return false end
    if not ( user.supports and user:supports( "HBRI" ) ) then return false end
    local claim = user._hbri_claim
    if not claim or not claim.ip or claim.ip == "" then return false end
    local main_fam = fam_of( user.ip( ) or "" )
    return claim.family == other_fam( main_fam )
end

-- // Begin HBRI: mint a token, register it, send the ITCP pointer to
-- // the hub's secondary-family listener.
-- //
-- // Login path (postlogin=false): the claim comes from user._hbri_claim
-- // (captured by the BINF handler) and the user is parked in the "hbri"
-- // state - enter_normal() is deferred until validate()/sweep() resolves.
-- // Post-login path (#286, postlogin=true): the claim is passed in from
-- // a NORMAL-state INF update; the user STAYS in NORMAL (adchpp keeps
-- // post-login HBRI flag-only, not state-changing) and a success simply
-- // broadcasts the now-complete INF (see commit_and_complete).
local function initiate( user, claim, postlogin )
    claim = claim or user._hbri_claim
    local sec_fam = claim.family
    local token   = adclib_createsalt( 16 )
    _tokens[ token ] = {
        user        = user,
        family      = sec_fam,
        claimed_udp = claim.udp,
        su_flags    = claim.su_flags or { },
        deadline    = os_time( ) + _timeout,
        postlogin   = postlogin or false,
    }
    user._hbri_token = token
    if not postlogin then user:state( "hbri" ) end
    -- ITCP I<fam><hub-addr> P<fam><port> TO<token>. The digit is the
    -- secondary family the client must validate over.
    local digit = ( sec_fam == "I6" ) and "6" or "4"
    user.write( "ITCP I" .. digit .. _advertise[ sec_fam ]
        .. " P" .. digit .. tostring( _port[ sec_fam ] )
        .. " TO" .. token .. "\n" )
end

-- // #286 post-login HBRI: a NORMAL-state INF update advertised a
-- // secondary family. The unverified secondary is still stripped from
-- // that broadcast by hub_inf_manager (the #97/#222 invariant holds);
-- // this solicits a side-channel to prove it and, on success, broadcasts
-- // the validated secondary. Called from the _normal.BINF dispatcher
-- // BEFORE the onInf strip, so it can read the secondary from adccmd.
local function postlogin_inf( user, adccmd )
    if not active( ) then return end
    if not ( user.supports and user:supports( "HBRI" ) ) then return end
    if user._hbri_token then return end    -- a validation is already in flight
    local sec_fam = other_fam( fam_of( user.ip( ) or "" ) )
    local sec_ip  = adccmd:getnp( sec_fam )
    if not sec_ip or sec_ip == "" then return end    -- family not offered
    -- Idempotent: the stored INF already carries a real (non-placeholder)
    -- secondary -> already validated, nothing to do. This is the primary
    -- guard against re-solicit storms (a client re-sends its full
    -- connectivity on every INF update). getpeername never yields a
    -- placeholder, so a committed value is always "real".
    -- Conservative by design: a client that LATER changes its secondary
    -- to a different real address is NOT re-validated (the old verified
    -- value keeps being broadcast until reconnect). This is fail-safe -
    -- an unverified new address is never broadcast, per #97 / #222 - not
    -- a bug; relaxing it would need a "secondary changed" re-validation
    -- path with its own loop guard.
    local inf = user:inf( )
    local cur = inf and inf:getnp( sec_fam )
    if cur and cur ~= "" and cur ~= "0.0.0.0" and cur ~= "::" then return end
    -- Backoff after a recent attempt - bounds the FAILED case.
    local now = os_time( )
    if user._hbri_postlogin_next and now < user._hbri_postlogin_next then return end
    user._hbri_postlogin_next = now + _POSTLOGIN_COOLDOWN
    local su_flags = { }
    local su = adccmd:getnp "SU"
    if su then
        local tcp_flag = ( sec_fam == "I6" ) and "TCP6" or "TCP4"
        local udp_flag = ( sec_fam == "I6" ) and "UDP6" or "UDP4"
        for tok in su:gmatch( "[^,]+" ) do
            if tok == tcp_flag or tok == udp_flag then
                su_flags[ #su_flags + 1 ] = tok
            end
        end
    end
    initiate( user, {
        family   = sec_fam,
        ip       = sec_ip,
        udp      = adccmd:getnp( ( sec_fam == "I6" ) and "U6" or "U4" ),
        su_flags = su_flags,
    }, true )
end

-- // Commit the verified secondary onto the main user's INF, then finish:
-- // login path runs the deferred NORMAL entry (which broadcasts the
-- // now-complete INF); post-login path (#286) broadcasts the updated INF
-- // directly, since the user is already in NORMAL.
local function commit_and_complete( entry, verified_ip )
    local user = entry.user
    local inf  = user:inf( )
    if inf then
        inf:setnp( entry.family, verified_ip )
        if entry.claimed_udp and entry.claimed_udp ~= "" then
            inf:setnp( ( entry.family == "I6" ) and "U6" or "U4", entry.claimed_udp )
        end
        -- Re-add the secondary transport flags that Gap 1 stripped.
        if #entry.su_flags > 0 then
            local su = inf:getnp "SU" or ""
            for _, flag in ipairs( entry.su_flags ) do
                if not su:find( flag, 1, true ) then
                    su = ( su == "" ) and flag or ( su .. "," .. flag )
                end
            end
            inf:setnp( "SU", su )
        end
    end
    user._hbri_token = nil
    if entry.postlogin then
        if inf then sendtoall( inf:adcstring( ) ) end
    else
        enter_normal( user )
    end
end

-- // Give up on the secondary. Login path: enter NORMAL with the
-- // secondary still stripped (the user stays connected, secondary
-- // unverified). Post-login path (#286): the user is already in NORMAL
-- // and the secondary was never broadcast, so there is nothing to undo -
-- // the next eligible INF can retry once the cooldown elapses.
local function fail( entry )
    local user = entry.user
    user._hbri_token = nil
    if not entry.postlogin then
        enter_normal( user )
    end
end

-- // Drop a pending attempt without completing login - used when the
-- // main user disconnects mid-HBRI so the token cannot dangle.
local function cancel( user )
    local token = user._hbri_token
    if token then
        _tokens[ token ] = nil
        user._hbri_token = nil
    end
end

-- // Handle an HTCP frame arriving on a fresh (transient) connection.
-- // `vuser` is that validation socket's throwaway user object; it is
-- // never entered into NORMAL and is closed here on every path.
local function validate( vuser, adccmd )
    local token = adccmd:getnp "TO"
    local entry = token and _tokens[ token ]
    if not entry then
        vuser.write( "ISTA 220 " .. _i18n_unknown_token .. "\n" )
        vuser:client( ):close( )
        return
    end
    _tokens[ token ] = nil    -- single-use

    -- Validation socket's real TCP source - the authenticated address.
    local vip  = vuser.ip( ) or ""
    local vfam = fam_of( vip )

    -- The validation socket MUST arrive on the expected secondary
    -- family (which is necessarily != the main connection's family).
    if vfam ~= entry.family then
        vuser.write( "ISTA 155 " .. _i18n_wrong_protocol .. "\n" )
        vuser:client( ):close( )
        fail( entry )
        return
    end

    -- #291: a placeholder (or absent) claimed value on the validation
    -- socket is a DISCOVERY request - "learn my address from this
    -- connection's source". Commit the authenticated getpeername (done
    -- below); the placeholder is not an address to cross-check. Only a
    -- CONCRETE stated address must equal the socket's real TCP source
    -- (anti-spoof of a self-named address). Mirrors adchpp validateIP.
    local claimed = adccmd:getnp( entry.family )
    if claimed and claimed ~= "" and claimed ~= "0.0.0.0" and claimed ~= "::"
            and claimed ~= vip then
        vuser.write( "ISTA 155 " .. _i18n_address_mismatch .. "\n" )
        vuser:client( ):close( )
        fail( entry )
        return
    end

    -- Success: commit the authenticated TCP-source IP (not the BINF
    -- claim - the side-channel source is ground truth).
    vuser.write( "ISTA 000 " .. _i18n_succeed .. "\n" )
    vuser:client( ):close( )
    commit_and_complete( entry, vip )
end

-- // Sweep timed-out attempts. Driven by hub.lua on the existing ~1s
-- // server timer. Resolves each expired attempt via fail() so the
-- // user proceeds into the hub without the unverified secondary.
local function sweep( )
    local now = os_time( )
    local expired
    for token, entry in pairs( _tokens ) do
        if now > entry.deadline then
            expired = expired or { }
            expired[ #expired + 1 ] = token
        end
    end
    if expired then
        for _, token in ipairs( expired ) do
            local entry = _tokens[ token ]
            if entry then
                _tokens[ token ] = nil
                local user = entry.user
                if user and not user.waskilled then
                    user.write( "ISTA 155 " .. _i18n_timeout .. "\n" )
                    fail( entry )
                end
            end
        end
    end
end

return {
    bind          = bind,
    set_i18n      = set_i18n,
    active        = active,
    eligible      = eligible,
    initiate      = initiate,
    postlogin_inf = postlogin_inf,
    validate      = validate,
    sweep         = sweep,
    cancel        = cancel,
}
