/*
 * zlib_stream.c - minimal zlib stream binding for luadch Phase 8 S4b.
 *
 * Two userdata types:
 *
 *   zlib_stream.deflate( [level] ) -> stream
 *       :push( input ) -> compressed bytes
 *
 *       Compresses `input` with deflate(..., Z_SYNC_FLUSH). Empty
 *       input still returns whatever output deflate flushes. Stateful:
 *       hold one of these per outbound TCP connection for its
 *       lifetime. `level` defaults to Z_DEFAULT_COMPRESSION (6); pass
 *       Z_BEST_SPEED (1) on heavily-loaded hubs that prefer CPU over
 *       bandwidth savings.
 *
 *   zlib_stream.inflate( ) -> stream
 *       :push( input ) -> decompressed bytes
 *
 *       Decompresses `input` with inflate(..., Z_SYNC_FLUSH). Caps the
 *       decompressed bytes produced PER PUSH CALL at 4 MiB
 *       (ZS_INFLATE_MAX_PER_PUSH below). Exceeding the cap throws a
 *       Lua error so the caller can recognise a decompression-bomb
 *       attempt and close the connection. The cap is high enough that
 *       a full 1 MiB ADC frame burst is comfortably handled, low
 *       enough that a 1 KB compressed bomb cannot drive multi-GiB
 *       allocations per tick.
 *
 *       Throws a Lua error on malformed compressed input (zlib
 *       Z_DATA_ERROR / Z_NEED_DICT). The caller is expected to log
 *       and close.
 *
 *   zlib_stream.gunzip( ) -> stream
 *       :push( input ) -> decompressed bytes
 *
 *       Like inflate(), but decodes the GZIP wrapper (RFC 1952) instead
 *       of the zlib wrapper (RFC 1950): inflateInit2(windowBits = 15+16).
 *       Reuses the inflate userdata/metatable, so :push / :close / __gc
 *       and the 4 MiB per-push bomb cap are identical. A non-gzip body
 *       (e.g. an HTML error page) is rejected with Z_DATA_ERROR on the
 *       first push. Used by core/geoip_update.lua to decompress the
 *       MaxMind GeoLite2 .tar.gz; feed the compressed file in bounded
 *       input chunks so the per-push OUTPUT stays under the 4 MiB cap.
 *
 *   :close()  -- frees the underlying zlib z_stream early
 *   __gc      -- safety net for forgotten :close()
 *
 * Design notes:
 *
 *   - Z_SYNC_FLUSH after EVERY push, on both sides. ADC-EXT explicitly
 *     mandates partial flush so the peer can decompress promptly; the
 *     trailing 00 00 FF FF sync marker is what makes the stream
 *     resumable mid-frame.
 *
 *   - We never call deflateReset / inflateReset. ADC's ZON/ZOF are
 *     stream-level signals; once a connection is in ZON mode the
 *     stream stays compressed until ZOF (which the hub handles by
 *     removing the iostream stage, not by resetting the zlib state).
 *
 *   - Output buffer growth: a single push may need multiple zlib
 *     output buffer rounds. We use a doubling 16 KB starter buffer
 *     (Lua's luaL_Buffer keeps it on the Lua stack); zlib doubles its
 *     consume rate. For the inflate cap we tally bytes across rounds.
 *
 *   - inflate() decodes the plain zlib stream ONLY (windowBits = 15,
 *     what ADC-EXT ZLIF mandates); gunzip() is the gzip-wrapper variant
 *     (windowBits = 15+16). No raw-deflate / custom-window-bits /
 *     dictionary support - the binding stays minimal.
 */

#include <string.h>
#include <stdlib.h>

#include <zlib.h>

#include <lua.h>
#include <lauxlib.h>

#define DEFLATE_META  "luadch.zlib_stream.deflate"
#define INFLATE_META  "luadch.zlib_stream.inflate"

/* Hard ceiling on decompressed bytes produced per :push call. 4 MiB
 * comfortably exceeds the largest plausible ADC frame burst (1 MiB
 * cap per frame, a handful per tick) while bounding the memory
 * pressure a single tick can drive. Exceeding this is treated as a
 * decompression-bomb attempt: the binding throws so the caller
 * can close the connection. */
#define ZS_INFLATE_MAX_PER_PUSH (4 * 1024 * 1024)

/* Initial output buffer chunk size. Most ADC frames fit; doubles as
 * needed inside the push loop. */
#define ZS_CHUNK 16384

typedef struct {
    z_stream strm;
    int      closed;
} zs_state;


/* ---------- shared helpers ---------- */

static zs_state *check_deflate( lua_State *L, int idx ) {
    return (zs_state *) luaL_checkudata( L, idx, DEFLATE_META );
}

static zs_state *check_inflate( lua_State *L, int idx ) {
    return (zs_state *) luaL_checkudata( L, idx, INFLATE_META );
}

static int zs_closed_error( lua_State *L, const char *side ) {
    return luaL_error( L, "zlib_stream: %s stream is closed", side );
}


/* ---------- deflate ---------- */

static int deflate_push( lua_State *L ) {
    zs_state *st = check_deflate( L, 1 );
    if ( st->closed ) {
        return zs_closed_error( L, "deflate" );
    }

    size_t in_len = 0;
    const char *in = luaL_checklstring( L, 2, &in_len );

    st->strm.next_in  = (Bytef *)( in_len ? in : "" );
    st->strm.avail_in = (uInt) in_len;

    luaL_Buffer b;
    luaL_buffinit( L, &b );

    /* deflate(Z_SYNC_FLUSH) until avail_out is non-zero (= zlib has
     * consumed all input and emitted everything pending). Empty
     * input still flushes any leftover compressor state - this is
     * what makes a "ZON\n" header line that goes through deflate
     * produce something on the wire even though it is short. */
    do {
        char *out = luaL_prepbuffsize( &b, ZS_CHUNK );
        st->strm.next_out  = (Bytef *) out;
        st->strm.avail_out = (uInt) ZS_CHUNK;

        int rc = deflate( &st->strm, Z_SYNC_FLUSH );
        if ( rc != Z_OK && rc != Z_BUF_ERROR ) {
            /* Z_STREAM_ERROR / Z_MEM_ERROR / etc. Never expected on
             * a sync-flush'ing live stream - surface it. */
            return luaL_error( L, "zlib_stream: deflate failed (rc=%d, msg=%s)",
                rc, st->strm.msg ? st->strm.msg : "?" );
        }

        size_t produced = ZS_CHUNK - st->strm.avail_out;
        luaL_addsize( &b, produced );

        /* Stop when zlib left output room AND no input remains: the
         * flush is complete. */
        if ( st->strm.avail_out > 0 && st->strm.avail_in == 0 ) {
            break;
        }
    } while ( 1 );

    luaL_pushresult( &b );
    return 1;
}

static int deflate_close( lua_State *L ) {
    zs_state *st = check_deflate( L, 1 );
    if ( !st->closed ) {
        deflateEnd( &st->strm );
        st->closed = 1;
    }
    return 0;
}

static int deflate_gc( lua_State *L ) {
    return deflate_close( L );
}

static int zlib_stream_deflate( lua_State *L ) {
    int level = (int) luaL_optinteger( L, 1, Z_DEFAULT_COMPRESSION );
    if ( level != Z_DEFAULT_COMPRESSION
         && ( level < Z_NO_COMPRESSION || level > Z_BEST_COMPRESSION ) ) {
        return luaL_error( L, "zlib_stream.deflate: invalid level %d", level );
    }

    zs_state *st = (zs_state *) lua_newuserdata( L, sizeof( zs_state ) );
    memset( st, 0, sizeof( *st ) );

    int rc = deflateInit( &st->strm, level );
    if ( rc != Z_OK ) {
        return luaL_error( L, "zlib_stream.deflate: deflateInit failed (rc=%d, msg=%s)",
            rc, st->strm.msg ? st->strm.msg : "?" );
    }

    luaL_setmetatable( L, DEFLATE_META );
    return 1;
}


/* ---------- inflate ---------- */

static int inflate_push( lua_State *L ) {
    zs_state *st = check_inflate( L, 1 );
    if ( st->closed ) {
        return zs_closed_error( L, "inflate" );
    }

    size_t in_len = 0;
    const char *in = luaL_checklstring( L, 2, &in_len );

    st->strm.next_in  = (Bytef *)( in_len ? in : "" );
    st->strm.avail_in = (uInt) in_len;

    luaL_Buffer b;
    luaL_buffinit( L, &b );

    size_t produced_total = 0;

    do {
        char *out = luaL_prepbuffsize( &b, ZS_CHUNK );
        st->strm.next_out  = (Bytef *) out;
        st->strm.avail_out = (uInt) ZS_CHUNK;

        int rc = inflate( &st->strm, Z_SYNC_FLUSH );
        if ( rc == Z_NEED_DICT || rc == Z_DATA_ERROR || rc == Z_MEM_ERROR ) {
            /* Malformed compressed input or out-of-memory. The caller
             * is expected to log and close - a sustained connection
             * cannot reasonably recover from a corrupted stream. */
            return luaL_error( L, "zlib_stream: inflate failed (rc=%d, msg=%s)",
                rc, st->strm.msg ? st->strm.msg : "?" );
        }
        /* Z_STREAM_END is legal: the remote sent a complete zlib
         * stream (rare in ADC ZLIF since the stream is open-ended,
         * but spec-permitted). We swallow trailing input. */

        size_t produced = ZS_CHUNK - st->strm.avail_out;
        produced_total += produced;
        if ( produced_total > ZS_INFLATE_MAX_PER_PUSH ) {
            return luaL_error(
                L,
                "zlib_stream: inflate output exceeds %d bytes per push (bomb guard)",
                ZS_INFLATE_MAX_PER_PUSH
            );
        }
        luaL_addsize( &b, produced );

        if ( rc == Z_STREAM_END ) {
            break;
        }
        /* Continue until zlib has consumed all input AND left output
         * room (= cannot produce more from current state). */
        if ( st->strm.avail_out > 0 && st->strm.avail_in == 0 ) {
            break;
        }
    } while ( 1 );

    luaL_pushresult( &b );
    return 1;
}

static int inflate_close( lua_State *L ) {
    zs_state *st = check_inflate( L, 1 );
    if ( !st->closed ) {
        inflateEnd( &st->strm );
        st->closed = 1;
    }
    return 0;
}

static int inflate_gc( lua_State *L ) {
    return inflate_close( L );
}

static int zlib_stream_inflate( lua_State *L ) {
    zs_state *st = (zs_state *) lua_newuserdata( L, sizeof( zs_state ) );
    memset( st, 0, sizeof( *st ) );

    int rc = inflateInit( &st->strm );
    if ( rc != Z_OK ) {
        return luaL_error( L, "zlib_stream.inflate: inflateInit failed (rc=%d, msg=%s)",
            rc, st->strm.msg ? st->strm.msg : "?" );
    }

    luaL_setmetatable( L, INFLATE_META );
    return 1;
}

static int zlib_stream_gunzip( lua_State *L ) {
    zs_state *st = (zs_state *) lua_newuserdata( L, sizeof( zs_state ) );
    memset( st, 0, sizeof( *st ) );

    /* windowBits 15 + 16 = 32 KiB window, GZIP (RFC 1952) wrapper ONLY.
     * gzip-only (not 15 + 32 auto-detect) so a non-gzip body is rejected
     * with Z_DATA_ERROR on the first :push rather than silently
     * mis-parsed. Reuses the inflate metatable below, so :push (with the
     * 4 MiB per-push bomb cap), :close and __gc are shared verbatim.
     * Decodes a SINGLE gzip member only (standard `tar czf` / MaxMind
     * output): a concatenated multi-member gzip would stop at the first
     * member's Z_STREAM_END and silently ignore the rest. Fine for the
     * GeoIP use case - the downstream tar-member + mmdb.open sanity checks
     * reject a truncated payload and keep the last-good DB. */
    int rc = inflateInit2( &st->strm, 15 + 16 );
    if ( rc != Z_OK ) {
        return luaL_error( L, "zlib_stream.gunzip: inflateInit2 failed (rc=%d, msg=%s)",
            rc, st->strm.msg ? st->strm.msg : "?" );
    }

    luaL_setmetatable( L, INFLATE_META );
    return 1;
}


/* ---------- module ---------- */

static const luaL_Reg deflate_methods[] = {
    { "push",  deflate_push  },
    { "close", deflate_close },
    { NULL, NULL },
};

static const luaL_Reg inflate_methods[] = {
    { "push",  inflate_push  },
    { "close", inflate_close },
    { NULL, NULL },
};

static const luaL_Reg module_funcs[] = {
    { "deflate", zlib_stream_deflate },
    { "inflate", zlib_stream_inflate },
    { "gunzip",  zlib_stream_gunzip  },
    { NULL, NULL },
};

static void register_meta( lua_State *L, const char *name, const luaL_Reg *methods, lua_CFunction gc ) {
    luaL_newmetatable( L, name );

    lua_pushvalue( L, -1 );
    lua_setfield( L, -2, "__index" );

    lua_pushcfunction( L, gc );
    lua_setfield( L, -2, "__gc" );

    luaL_setfuncs( L, methods, 0 );

    lua_pop( L, 1 );
}

int luaopen_zlib_stream( lua_State *L ) {
    register_meta( L, DEFLATE_META, deflate_methods, deflate_gc );
    register_meta( L, INFLATE_META, inflate_methods, inflate_gc );

    lua_newtable( L );
    luaL_setfuncs( L, module_funcs, 0 );

    /* Expose zlib version + the per-push cap so callers can log it /
     * tests can assert it. */
    lua_pushstring( L, zlibVersion( ) );
    lua_setfield( L, -2, "version" );

    lua_pushinteger( L, ZS_INFLATE_MAX_PER_PUSH );
    lua_setfield( L, -2, "inflate_max_per_push" );

    return 1;
}
