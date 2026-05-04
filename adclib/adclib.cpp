/*
 * This code is partially copied from 
 *  - DCNet-X ADC Server Project ( http://dcnet-x.sourceforge.net )
 *  - ADCH++ ( http://sourceforge.net/projects/adchpp )
 *  - DC++ ( http://sourceforge.net/projects/dcplusplus )
 * 
 */

#include <cstdint>
#include <cstddef>
#include <string>

#include "includes.h"
#include "base32.h"
#include "tiger.h"

#include <openssl/rand.h>
#include <openssl/evp.h>

extern "C" {

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

}

// AES-GCM constants. The Lua wrapper in core/cfg_secret.lua enforces
// the same constants for framing on disk.
enum {
    AES_KEY_SIZE = 32,    // AES-256
    AES_NONCE_SIZE = 12,  // GCM standard 96-bit nonce
    AES_TAG_SIZE = 16,    // GCM standard 128-bit tag
};

enum {SIZE = 192/8};

// Bounded buffer sizes for the Tiger hash inputs. The legitimate ADC
// CID is exactly SIZE (24) bytes; the legitimate ADC salt is bounded by
// adclib.createsalt's default of 10 base32 chars (~6 bytes). MAX_SALT_BYTES
// is set well above that so any reasonable future tuning of createsalt
// fits, while still preventing the attacker-sized VLA stack-DoS flagged
// as F-C-1 in the Phase 7 audit.
enum {MAX_SALT_BYTES = 64};

int utf8ToWc(const char* str, wchar_t& c) {
        const auto c0 = static_cast<uint8_t>(str[0]);
        const auto bytes = 2 + !!(c0 & 0x20) + ((c0 & 0x30) == 0x30);

        if ((c0 & 0xc0) == 0xc0) {                  // 11xx xxxx
                                                    // # bytes of leading 1's; check for 0 next
                const auto check_bit = 1 << (7 - bytes);
                if (c0 & check_bit)
                        return -1;

                c = (check_bit - 1) & c0;

                // 2-4 total, or 1-3 additional, bytes
                // Can't run off end of str so long as has sub-0x80-terminator
                for (auto i = 1; i < bytes; ++i) {
                        const auto ci = static_cast<uint8_t>(str[i]);
                        if ((ci & 0xc0) != 0x80)
                                return -i;
                        c = (c << 6) | (ci & 0x3f);
                }

                // Invalid UTF-8 code points
                if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) {
                        // "REPLACEMENT CHARACTER": used to replace an incoming character
                        // whose value is unknown or unrepresentable in Unicode
                        c = 0xfffd;
                        return -bytes;
                }

                return bytes;
        } else if ((c0 & 0x80) == 0) {             // 0xxx xxxx
                c = static_cast<unsigned char>(str[0]);
                return 1;
        } else {                                   // 10xx xxxx
                return -1;
        }
}

// NOTE: this won't handle UTF-16 surrogate pairs
void wcToUtf8(wchar_t c, std::string& str) {
        // https://tools.ietf.org/html/rfc3629#section-3
        if (c > 0x10ffff || (c >= 0xd800 && c <= 0xdfff)) {
                // Invalid UTF-8 code point
                // REPLACEMENT CHARACTER: http://www.fileformat.info/info/unicode/char/0fffd/index.htm
                wcToUtf8(0xfffd, str);
        } else if (c >= 0x10000) {
                str += (char)(0x80 | 0x40 | 0x20 | 0x10 | (c >> 18));
                str += (char)(0x80 | ((c >> 12) & 0x3f));
                str += (char)(0x80 | ((c >> 6) & 0x3f));
                str += (char)(0x80 | (c & 0x3f));
        } else if (c >= 0x0800) {
                str += (char)(0x80 | 0x40 | 0x20 | (c >> 12));
                str += (char)(0x80 | ((c >> 6) & 0x3f));
                str += (char)(0x80 | (c & 0x3f));
        } else if (c >= 0x0080) {
                str += (char)(0x80 | 0x40 | (c >> 6));
                str += (char)(0x80 | (c & 0x3f));
        } else {
                str += (char)c;
        }
}

std::string sanitizeUtf8(const std::string& str) noexcept {
        std::string tgt;
        tgt.reserve(str.length());

        const auto n = str.length();
        for (std::string::size_type i = 0; i < n; ) {
                wchar_t c = 0;
                int x = utf8ToWc(str.c_str() + i, c);
                if (x < 0) {
                        tgt.insert(i, abs(x), '_');
                } else {
                        wcToUtf8(c, tgt);
                }

                i += abs(x);
        }

        return tgt;
}

bool validateUtf8(const std::string& str) noexcept {
        std::string::size_type i = 0;
        while (i < str.length()) {
                wchar_t dummy = 0;
                int j = utf8ToWc(&str[i], dummy);
                if (j < 0)
                        return false;
                i += j;
        }
        return true;
}

int sanitize_utf8(lua_State* L)
{
    size_t length;
    std::string buf = luaL_checklstring(L, 1, &length);
    std::string result = sanitizeUtf8(buf);
    lua_pushlstring(L, result.c_str(), result.length());
    return 1;
}

int is_valid_utf8(lua_State* L)
{
    size_t length;
    std::string buf = luaL_checklstring(L, 1, &length);
    validateUtf8(buf) ? lua_pushboolean(L, 1) : lua_pushboolean(L, 0);
    return 1;
}

// All three hash_* functions take Lua strings that may legitimately
// contain embedded NUL bytes (passwords, binary CID/PID material), so
// they use luaL_checklstring with explicit length to avoid the silent
// truncation flagged as F-C-3. Salt and CID are also bounded against
// the attacker-sized-VLA stack-DoS flagged as F-C-1.

int hash_pid(lua_State* L)
{
    size_t pid_len;
    const char* pid_data = luaL_checklstring(L, 1, &pid_len);
    unsigned char cid[SIZE];

    memset(cid, 0, sizeof(cid));
    ADCLIB::BASE32::FROMBASE32(pid_data, cid, sizeof(cid));
    ADCLIB::TigerHash Tiger;
    Tiger.update(cid, SIZE);
    Tiger.finalize();
    std::string result = ADCLIB::BASE32::TOBASE32(Tiger.getResult(), ADCLIB::TigerHash::HASH_SIZE);
    lua_pushlstring(L, result.c_str(), result.length());
    return 1;
}

int hash_pas(lua_State* L)
{
    size_t pass_len, salt_len;
    const char* pass_data = luaL_checklstring(L, 1, &pass_len);
    const char* salt_data = luaL_checklstring(L, 2, &salt_len);

    size_t saltBytes = salt_len * 5 / 8;
    if (saltBytes == 0 || saltBytes > MAX_SALT_BYTES) {
        return luaL_error(L, "hashpas: salt length %zu out of range",
                          saltBytes);
    }
    unsigned char chunk[MAX_SALT_BYTES];

    memset(chunk, 0, saltBytes);
    ADCLIB::BASE32::FROMBASE32(salt_data, chunk, saltBytes);
    ADCLIB::TigerHash Tiger;
    Tiger.update(pass_data, pass_len);
    Tiger.update(chunk, saltBytes);
    Tiger.finalize();
    std::string result = ADCLIB::BASE32::TOBASE32(Tiger.getResult(), ADCLIB::TigerHash::HASH_SIZE);
    lua_pushlstring(L, result.c_str(), result.length());
    return 1;
}

int hash_pas_oldschool(lua_State* L)
{
    size_t pass_len, salt_len, cid_len;
    const char* pass_data = luaL_checklstring(L, 1, &pass_len);
    const char* salt_data = luaL_checklstring(L, 2, &salt_len);
    const char* cid_data = luaL_checklstring(L, 3, &cid_len);

    size_t saltBytes = salt_len * 5 / 8;
    if (saltBytes == 0 || saltBytes > MAX_SALT_BYTES) {
        return luaL_error(L, "hasholdpas: salt length %zu out of range",
                          saltBytes);
    }
    unsigned char chunk1[MAX_SALT_BYTES];
    unsigned char chunk2[SIZE];
    memset(chunk1, 0, saltBytes);
    memset(chunk2, 0, sizeof(chunk2));
    ADCLIB::BASE32::FROMBASE32(salt_data, chunk1, saltBytes);
    ADCLIB::BASE32::FROMBASE32(cid_data, chunk2, sizeof(chunk2));
    ADCLIB::TigerHash Tiger;
    Tiger.update(chunk2, SIZE);
    Tiger.update(pass_data, pass_len);
    Tiger.update(chunk1, saltBytes);
    Tiger.finalize();
    std::string result = ADCLIB::BASE32::TOBASE32(Tiger.getResult(), ADCLIB::TigerHash::HASH_SIZE);
    lua_pushlstring(L, result.c_str(), result.length());
    return 1;
}

// CSPRNG: returns n cryptographically strong random bytes as a Lua string.
// Backed by OpenSSL RAND_bytes (libcrypto). Replaces the math.random()-based
// salt source flagged as F-AUTH-2 in the Phase 7 audit.
int random_bytes(lua_State* L)
{
    lua_Integer n = luaL_checkinteger(L, 1);
    if (n <= 0 || n > 4096) {
        return luaL_error(L, "random_bytes: n must be in [1, 4096], got %d",
                          (int)n);
    }
    unsigned char buf[4096];
    if (RAND_bytes(buf, (int)n) != 1) {
        return luaL_error(L, "random_bytes: RAND_bytes failed (PRNG not seeded)");
    }
    lua_pushlstring(L, (const char *)buf, (size_t)n);
    return 1;
}

// AES-256-GCM seal: takes (key, nonce, plaintext), returns
// ciphertext || tag concatenated as one Lua string. The plaintext can
// be any binary; key must be exactly 32 bytes, nonce exactly 12 bytes.
// Phase 7f F-AUTH-1 mitigation: at-rest encryption of user.tbl.
int aes_gcm_seal(lua_State* L)
{
    size_t key_len, nonce_len, pt_len;
    const unsigned char* key = (const unsigned char*)luaL_checklstring(L, 1, &key_len);
    const unsigned char* nonce = (const unsigned char*)luaL_checklstring(L, 2, &nonce_len);
    const unsigned char* pt = (const unsigned char*)luaL_checklstring(L, 3, &pt_len);

    if (key_len != AES_KEY_SIZE) {
        return luaL_error(L, "aes_gcm_seal: key must be %d bytes, got %d",
                          AES_KEY_SIZE, (int)key_len);
    }
    if (nonce_len != AES_NONCE_SIZE) {
        return luaL_error(L, "aes_gcm_seal: nonce must be %d bytes, got %d",
                          AES_NONCE_SIZE, (int)nonce_len);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return luaL_error(L, "aes_gcm_seal: EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return luaL_error(L, "aes_gcm_seal: EVP_EncryptInit_ex failed");
    }

    luaL_Buffer b;
    luaL_buffinit(L, &b);
    // Allocate space for ciphertext (same size as plaintext for GCM) + tag.
    unsigned char* out = (unsigned char*)luaL_prepbuffsize(&b, pt_len + AES_TAG_SIZE);

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, out, &outlen, pt, (int)pt_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return luaL_error(L, "aes_gcm_seal: EVP_EncryptUpdate failed");
    }
    int finlen = 0;
    if (EVP_EncryptFinal_ex(ctx, out + outlen, &finlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return luaL_error(L, "aes_gcm_seal: EVP_EncryptFinal_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE,
                            out + outlen + finlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return luaL_error(L, "aes_gcm_seal: EVP_CTRL_GCM_GET_TAG failed");
    }
    EVP_CIPHER_CTX_free(ctx);

    luaL_addsize(&b, outlen + finlen + AES_TAG_SIZE);
    luaL_pushresult(&b);
    return 1;
}

// AES-256-GCM open: takes (key, nonce, ciphertext_with_tag), returns
// plaintext on success or (nil, error_message) on tag-mismatch or
// malformed input. Tag-mismatch is the security-critical signal: a
// tampered file fails here.
int aes_gcm_open(lua_State* L)
{
    size_t key_len, nonce_len, blob_len;
    const unsigned char* key = (const unsigned char*)luaL_checklstring(L, 1, &key_len);
    const unsigned char* nonce = (const unsigned char*)luaL_checklstring(L, 2, &nonce_len);
    const unsigned char* blob = (const unsigned char*)luaL_checklstring(L, 3, &blob_len);

    if (key_len != AES_KEY_SIZE) {
        return luaL_error(L, "aes_gcm_open: key must be %d bytes, got %d",
                          AES_KEY_SIZE, (int)key_len);
    }
    if (nonce_len != AES_NONCE_SIZE) {
        return luaL_error(L, "aes_gcm_open: nonce must be %d bytes, got %d",
                          AES_NONCE_SIZE, (int)nonce_len);
    }
    if (blob_len < AES_TAG_SIZE) {
        lua_pushnil(L);
        lua_pushstring(L, "ciphertext shorter than tag");
        return 2;
    }
    size_t ct_len = blob_len - AES_TAG_SIZE;
    const unsigned char* ct = blob;
    const unsigned char* tag = blob + ct_len;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return luaL_error(L, "aes_gcm_open: EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return luaL_error(L, "aes_gcm_open: EVP_DecryptInit_ex failed");
    }

    luaL_Buffer b;
    luaL_buffinit(L, &b);
    unsigned char* out = (unsigned char*)luaL_prepbuffsize(&b, ct_len);

    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, out, &outlen, ct, (int)ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "EVP_DecryptUpdate failed");
        return 2;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE,
                            (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "EVP_CTRL_GCM_SET_TAG failed");
        return 2;
    }
    int finlen = 0;
    if (EVP_DecryptFinal_ex(ctx, out + outlen, &finlen) != 1) {
        // Tag mismatch - tampering or wrong key.
        EVP_CIPHER_CTX_free(ctx);
        lua_pushnil(L);
        lua_pushstring(L, "tag mismatch (file tampered or wrong key)");
        return 2;
    }
    EVP_CIPHER_CTX_free(ctx);

    luaL_addsize(&b, outlen + finlen);
    luaL_pushresult(&b);
    return 1;
}

int escape(lua_State* L)
{
    std::string s = (std::string) luaL_optstring(L, 1, "");
    std::string out = "";
    out.reserve(out.length() + static_cast<size_t>(s.length()*1.1));
    std::string::const_iterator send = s.end();
    for(std::string::const_iterator i = s.begin(); i != send; ++i)
    {
        switch(*i)
        {
            case ' ': out += "\\s"; break;
            case '\n': out += "\\n"; break;
            case '\\': out += "\\\\"; break;
            default: out += *i;
        }
    }
    lua_pushlstring(L, out.c_str(), out.length());
    return 1;
}

int unescape(lua_State* L)
{
    std::string s = (std::string) luaL_optstring(L, 1, "");
    std::string out = "";
    out.reserve(out.length() + static_cast<size_t>(s.length()*1.1));
    std::string::const_iterator send = s.end();
    for(std::string::const_iterator i = s.begin(); i != send; ++i)
    {
        switch(*i)
        {
            case '\\':
                if ((i + 1) != send)
                {
                    ++i;
                    if ('s' == *i)
                        out += ' ';
                    if ('n' == *i)
                        out += '\n';
                    if ('\\' == *i)
                        out += '\\';
                }
                break;
            default: out += *i;
        }
    }
    lua_pushlstring(L, out.c_str(), out.length());
    return 1;
}

static const luaL_Reg adclib[] = {
    {"hash", hash_pid},
    {"hashpas", hash_pas},
    {"hasholdpas", hash_pas_oldschool},
    {"escape", escape},
    {"unescape", unescape},
    {"isutf8", is_valid_utf8},
    {"sanitize_utf8", sanitize_utf8},
    {"random_bytes", random_bytes},
    {"aes_gcm_seal", aes_gcm_seal},
    {"aes_gcm_open", aes_gcm_open},
    {NULL, NULL}
};

extern "C" int luaopen_adclib(lua_State* L)
{
    luaL_newlib(L, adclib);
    return 1;
}

