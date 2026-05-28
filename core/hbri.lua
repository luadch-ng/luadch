--[[

    hbri.lua - HBRI (Hub-Bridged Reverse Initiation), #214.

    Verifies a dual-stack client's SECONDARY IP family over a
    second-family side-channel TCP connection, so the hub can safely
    broadcast it. Without HBRI the secondary family is stripped before
    broadcast (#214 Gap 1, core/hub_dispatch.lua) because the hub has
    no socket on the other family through which to authenticate the
    claimed address - broadcasting an unverified secondary is a DC++
    DDoS-amplification vector.

    Flow (client main connection on family X, secondary family Y):

      1. Client advertises ADHBRI in HSUP and a secondary IY in BINF.
         core/hub_dispatch.lua captures the claim (user._hbri_claim)
         BEFORE Gap 1 strips it.
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
         the validation-socket TCP source IP == the claimed address.
         On success the verified secondary is committed to the main
         user's INF and the user enters NORMAL (now broadcasting the
         validated secondary). On any failure - or a timeout swept by
         sweep() on the ~1s hub timer - the user enters NORMAL anyway
         with the secondary left stripped (failHBRI).

    No core/server.lua change: the validation socket rides the normal
    accept path and is identified purely by its HTCP+token first frame.

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
local _enabled               -- hbri_enabled cfg
local _timeout               -- hbri_timeout seconds (clamped)
local _advertise = { I4 = "", I6 = "" }   -- hub public address per family
local _port      = { I4 = nil,  I6 = nil } -- plain listener port per family
local _dual_stack = false    -- a plain listener exists on BOTH families

-- // token table: token -> {
-- //   user        = main user object,
-- //   family      = expected secondary family ("I4" | "I6"),
-- //   claimed_ip  = secondary address the client advertised in BINF,
-- //   claimed_udp = secondary UDP port (string) or nil,
-- //   su_flags    = { secondary transport flags present in BINF SU },
-- //   deadline    = os.time() second past which the attempt times out,
-- // }
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
    _enabled     = deps.hbri_enabled and true or false
    _timeout     = deps.hbri_timeout
    _advertise.I4 = deps.hbri_advertise_v4 or ""
    _advertise.I6 = deps.hbri_advertise_v6 or ""
    _port.I4      = deps.hbri_port_v4
    _port.I6      = deps.hbri_port_v6
    _dual_stack   = deps.hbri_dual_stack and true or false
end

-- // Hub can drive HBRI at all: enabled, both families have a plain
-- // listener, and both public advertise addresses are configured.
-- // (Advertised in SUP only when this holds, so a client never gets
-- // an ITCP it cannot reach.)
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
-- // the hub's secondary-family listener, and park the user in the
-- // "hbri" state. enter_normal() is deferred until validate() or
-- // sweep() resolves the attempt.
local function initiate( user )
    local claim   = user._hbri_claim
    local sec_fam = claim.family
    local token   = adclib_createsalt( 16 )
    _tokens[ token ] = {
        user        = user,
        family      = sec_fam,
        claimed_ip  = claim.ip,
        claimed_udp = claim.udp,
        su_flags    = claim.su_flags or { },
        deadline    = os_time( ) + _timeout,
    }
    user._hbri_token = token
    user:state( "hbri" )
    -- ITCP I<fam><hub-addr> P<fam><port> TO<token>. The digit is the
    -- secondary family the client must validate over.
    local digit = ( sec_fam == "I6" ) and "6" or "4"
    user.write( "ITCP I" .. digit .. _advertise[ sec_fam ]
        .. " P" .. digit .. tostring( _port[ sec_fam ] )
        .. " TO" .. token .. "\n" )
end

-- // Commit the verified secondary onto the main user's INF, then run
-- // the deferred NORMAL entry (which broadcasts the now-complete INF).
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
    enter_normal( user )
end

-- // Give up on the secondary: drop the ADHBRI support flag (no
-- // post-login retry loop) and enter NORMAL with the secondary still
-- // stripped. The user stays connected; only the secondary family is
-- // unverified.
local function fail( entry )
    local user = entry.user
    user._hbri_token = nil
    enter_normal( user )
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
        vuser.write( "ISTA 220 " .. "Unknown\\svalidation\\stoken" .. "\n" )
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
        vuser.write( "ISTA 155 " .. "Validation\\srequest\\son\\swrong\\sIP\\sprotocol" .. "\n" )
        vuser:client( ):close( )
        fail( entry )
        return
    end

    -- The address the client claims on the validation socket must
    -- match the socket's real TCP source (anti-spoof).
    local claimed = adccmd:getnp( entry.family )
    if claimed and claimed ~= vip then
        vuser.write( "ISTA 155 " .. "Validation\\saddress\\smismatch" .. "\n" )
        vuser:client( ):close( )
        fail( entry )
        return
    end

    -- Success: commit the authenticated TCP-source IP (not the BINF
    -- claim - the side-channel source is ground truth).
    vuser.write( "ISTA 000 " .. "Validation\\ssucceed" .. "\n" )
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
                    user.write( "ISTA 155 " .. "Secondary\\saddress\\svalidation\\stimed\\sout" .. "\n" )
                    fail( entry )
                end
            end
        end
    end
end

return {
    bind     = bind,
    active   = active,
    eligible = eligible,
    initiate = initiate,
    validate = validate,
    sweep    = sweep,
    cancel   = cancel,
}
