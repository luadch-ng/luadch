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
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#include <climits>

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

// Push (nil, "<prefix>: <openssl-reason>") onto the Lua stack, drain
// the OpenSSL per-thread error queue, return 2 (Lua "soft" error
// shape: caller does `local ok, err = adclib.foo(...)` and inspects
// err). The OpenSSL reason is included for diagnostic context;
// callers in cert_bootstrap.lua surface it via out.error.
//
// Hygiene: every OpenSSL-using adclib entry point calls
// ERR_clear_error() on entry so the per-thread queue starts clean.
// On error this helper drains again, so the queue is empty at
// every public API boundary.
static int push_ossl_err(lua_State* L, const char* prefix)
{
    unsigned long e = ERR_get_error();
    char buf[256];
    lua_pushnil(L);
    if (e) {
        ERR_error_string_n(e, buf, sizeof(buf));
        lua_pushfstring(L, "%s: %s", prefix, buf);
    } else {
        lua_pushstring(L, prefix);
    }
    ERR_clear_error();
    return 2;
}

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
    ERR_clear_error();    // start with empty per-thread OpenSSL error queue

    lua_Integer n = luaL_checkinteger(L, 1);
    if (n <= 0 || n > 4096) {
        return luaL_error(L, "random_bytes: n must be in [1, 4096], got %d",
                          (int)n);
    }
    unsigned char buf[4096];
    if (RAND_bytes(buf, (int)n) != 1) {
        ERR_clear_error();
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
    ERR_clear_error();    // start with empty per-thread OpenSSL error queue
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
        ERR_clear_error();
        return luaL_error(L, "aes_gcm_seal: EVP_EncryptInit_ex failed");
    }

    luaL_Buffer b;
    luaL_buffinit(L, &b);
    // Allocate space for ciphertext (same size as plaintext for GCM) + tag.
    unsigned char* out = (unsigned char*)luaL_prepbuffsize(&b, pt_len + AES_TAG_SIZE);

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, out, &outlen, pt, (int)pt_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ERR_clear_error();
        return luaL_error(L, "aes_gcm_seal: EVP_EncryptUpdate failed");
    }
    int finlen = 0;
    if (EVP_EncryptFinal_ex(ctx, out + outlen, &finlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ERR_clear_error();
        return luaL_error(L, "aes_gcm_seal: EVP_EncryptFinal_ex failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AES_TAG_SIZE,
                            out + outlen + finlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        ERR_clear_error();
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
    ERR_clear_error();    // start with empty per-thread OpenSSL error queue
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
        ERR_clear_error();
        return luaL_error(L, "aes_gcm_open: EVP_DecryptInit_ex failed");
    }

    luaL_Buffer b;
    luaL_buffinit(L, &b);
    unsigned char* out = (unsigned char*)luaL_prepbuffsize(&b, ct_len);

    int outlen = 0;
    if (EVP_DecryptUpdate(ctx, out, &outlen, ct, (int)ct_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return push_ossl_err(L, "EVP_DecryptUpdate failed");
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AES_TAG_SIZE,
                            (void*)tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        return push_ossl_err(L, "EVP_CTRL_GCM_SET_TAG failed");
    }
    int finlen = 0;
    if (EVP_DecryptFinal_ex(ctx, out + outlen, &finlen) != 1) {
        // Tag mismatch - tampering or wrong key.
        EVP_CIPHER_CTX_free(ctx);
        // Note: tag-mismatch is a security signal, not a diagnostic.
        // Keep the existing operator-friendly message; drain the
        // queue separately so it does not leak across calls.
        lua_pushnil(L);
        lua_pushstring(L, "tag mismatch (file tampered or wrong key)");
        ERR_clear_error();
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

// Self-signed cert generation (#77 TLS-only default).
// Lua signature:  key_pem, cert_pem = adclib.gen_self_signed_cert(cn, days)
//                 nil, err          (on error)
// Generates an ECDSA P-256 keypair, builds an X509 v3 self-signed
// certificate with subject CN = `cn`, validity now..now+days, signs
// it with SHA-256, and returns both as PEM strings. The Lua wrapper
// in core/cert_bootstrap.lua writes them to certs/serverkey.pem +
// certs/servercert.pem on first boot when no cert is present.
int gen_self_signed_cert(lua_State* L)
{
    ERR_clear_error();    // start with empty per-thread OpenSSL error queue

    const char* cn = luaL_checkstring(L, 1);
    lua_Integer days_in = luaL_checkinteger(L, 2);

    // Defensive bound on validity period. 24855 days (~68 years) is
    // the largest value that fits in the smallest `long` we support
    // (32-bit) when multiplied by 86400 seconds/day:
    //   LONG_MAX / 86400 = 2,147,483,647 / 86400 = 24855 (32-bit long)
    // The bound is platform-independent: applies the same on 32-bit
    // ILP32 (i686 / ARMv7 / MIPS32) AND on Windows x64 LLP64
    // (MinGW UCRT64 / MSVC) where `long` is also 32-bit by Windows
    // ABI. On Linux LP64 (x86_64 / aarch64) where `long` is 64-bit
    // the bound is harmless but unifies the operator-facing behaviour
    // across all platforms. A self-signed cert never realistically
    // wants > 68 years; cert_bootstrap defaults to 3650 days (10y).
    //
    // Closes #208 (prior 36500-day bound combined with `long`
    // multiplication overflowed for days > 24855 on long-is-32-bit
    // platforms, producing a `notAfter` ~1933 - cert was already
    // expired at generation and adcs:// became unreachable).
    if (days_in < 1 || days_in > 24855) {
        lua_pushnil(L);
        lua_pushfstring(L,
            "gen_self_signed_cert: days must be in [1, 24855] (~68 years), got %I",
            days_in);
        return 2;
    }

    EVP_PKEY* pkey = NULL;
    X509* x509 = NULL;
    BIO* key_bio = NULL;
    BIO* cert_bio = NULL;

    // P-256 ECDSA key. EVP_EC_gen() is the OpenSSL 3.0 fluent API; on
    // 1.1.1 we would have to fall back to EVP_PKEY_CTX_new_id +
    // EVP_PKEY_keygen_init + EVP_PKEY_CTX_set_ec_paramgen_curve_nid.
    // luadch links against OpenSSL 3.x in both Linux and Windows
    // builds (Phase 4 audit), so EVP_EC_gen is fine here.
    pkey = EVP_EC_gen("P-256");
    if (!pkey) {
        return push_ossl_err(L, "EVP_EC_gen P-256 failed");
    }

    x509 = X509_new();
    if (!x509) {
        EVP_PKEY_free(pkey);
        return push_ossl_err(L, "X509_new failed");
    }

    // Version 3 (the integer field stores version - 1, so 2 means v3).
    X509_set_version(x509, 2);

    // Random 128-bit serial. Top bit cleared so the BN -> ASN.1 INTEGER
    // conversion stays positive (some clients reject negative serials).
    unsigned char serial_bytes[16];
    if (RAND_bytes(serial_bytes, sizeof(serial_bytes)) != 1) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return push_ossl_err(L, "RAND_bytes for serial failed");
    }
    serial_bytes[0] &= 0x7F;
    BIGNUM* serial_bn = BN_bin2bn(serial_bytes, sizeof(serial_bytes), NULL);
    if (!serial_bn) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return push_ossl_err(L, "BN_bin2bn for serial failed");
    }
    BN_to_ASN1_INTEGER(serial_bn, X509_get_serialNumber(x509));
    BN_free(serial_bn);

    // Validity: now to now + days*86400 seconds. The 24855-day input
    // bound guarantees `days * 86400 <= 2,147,472,000 < LONG_MAX` on
    // every supported platform, so direct `long` arithmetic is safe.
    long days = (long)days_in;
    X509_gmtime_adj(X509_getm_notBefore(x509), 0);
    X509_gmtime_adj(X509_getm_notAfter(x509), days * 86400);

    X509_set_pubkey(x509, pkey);

    // Subject == issuer (self-signed). The CN string comes from a
    // random 128-bit value (formatted hex) in cert_bootstrap.lua so
    // each fresh deployment gets a distinct fingerprint.
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char*)cn, -1, -1, 0);
    X509_set_issuer_name(x509, name);

    if (!X509_sign(x509, pkey, EVP_sha256())) {
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return push_ossl_err(L, "X509_sign failed");
    }

    // PEM-serialize key (PKCS#8 unencrypted) and cert.
    key_bio = BIO_new(BIO_s_mem());
    cert_bio = BIO_new(BIO_s_mem());
    if (!key_bio || !cert_bio) {
        if (key_bio) BIO_free(key_bio);
        if (cert_bio) BIO_free(cert_bio);
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return push_ossl_err(L, "BIO_new failed");
    }

    if (!PEM_write_bio_PrivateKey(key_bio, pkey, NULL, NULL, 0, NULL, NULL)) {
        BIO_free(key_bio); BIO_free(cert_bio);
        X509_free(x509); EVP_PKEY_free(pkey);
        return push_ossl_err(L, "PEM_write_bio_PrivateKey failed");
    }
    if (!PEM_write_bio_X509(cert_bio, x509)) {
        BIO_free(key_bio); BIO_free(cert_bio);
        X509_free(x509); EVP_PKEY_free(pkey);
        return push_ossl_err(L, "PEM_write_bio_X509 failed");
    }

    BUF_MEM* key_buf = NULL;
    BUF_MEM* cert_buf = NULL;
    BIO_get_mem_ptr(key_bio, &key_buf);
    BIO_get_mem_ptr(cert_bio, &cert_buf);

    lua_pushlstring(L, key_buf->data, key_buf->length);
    lua_pushlstring(L, cert_buf->data, cert_buf->length);

    BIO_free(key_bio);
    BIO_free(cert_bio);
    X509_free(x509);
    EVP_PKEY_free(pkey);
    return 2;
}

// SHA-256 fingerprint of a PEM-encoded X509 certificate.
// Lua signature:  raw_32_bytes = adclib.cert_fingerprint_sha256(cert_pem)
//                 nil, err     (on error)
// Caller is expected to base32-encode the 32 raw bytes for the
// adcs://host:port/?kp=SHA256/<base32> URL form.
int cert_fingerprint_sha256(lua_State* L)
{
    ERR_clear_error();    // start with empty per-thread OpenSSL error queue

    size_t cert_len;
    const char* cert_pem = luaL_checklstring(L, 1, &cert_len);

    // Defensive: BIO_new_mem_buf takes int. A cert > INT_MAX bytes
    // is implausible for a hub deployment (real certs are ~500 B)
    // but guards against caller misuse where a huge buffer would
    // wrap to a negative length and BIO would interpret as
    // "use strlen", reading past intended bounds.
    if (cert_len > (size_t)INT_MAX) {
        lua_pushnil(L);
        lua_pushstring(L, "cert_fingerprint_sha256: cert PEM exceeds INT_MAX");
        return 2;
    }

    BIO* bio = BIO_new_mem_buf(cert_pem, (int)cert_len);
    if (!bio) {
        return push_ossl_err(L, "BIO_new_mem_buf failed");
    }

    X509* cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    BIO_free(bio);
    if (!cert) {
        return push_ossl_err(L, "PEM_read_bio_X509 failed");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;
    if (!X509_digest(cert, EVP_sha256(), hash, &hash_len)) {
        X509_free(cert);
        return push_ossl_err(L, "X509_digest failed");
    }
    X509_free(cert);

    lua_pushlstring(L, (const char*)hash, hash_len);
    return 1;
}

// Constant-time string equality (#82 Phase 1c). Compares two Lua
// strings byte-for-byte without short-circuiting at the first
// mismatch - the loop fully unrolls over the shorter operand so
// timing does not leak the position of the first differing byte
// the way `==` does. Used by core/http_router.lua's resolve_token
// to compare an incoming Bearer token against the cfg.http_api_tokens
// keys; the pure-Lua fallback in http_router.lua applies the same
// algorithm if adclib failed to load.
//
// Lua signature:  bool = adclib.constant_time_eq(a, b)
//   - both must be strings (any byte content, including NUL)
//   - returns false if either is not a string or if lengths differ
//     (length itself is not the secret in our use case; the cfg key
//     IS the token, the operator picked it)
//   - returns true iff lengths match AND every byte matches
//
// Differs from random_bytes / hash_pas: no error path, no OpenSSL
// (pure CPU op), no size limits (Lua's string-length cap applies).
int constant_time_eq(lua_State* L)
{
    size_t a_len, b_len;
    // luaL_checklstring is the explicit-length form (matches the
    // F-C-3 hardening pattern: any byte content allowed, NULs OK).
    const char* a = luaL_checklstring(L, 1, &a_len);
    const char* b = luaL_checklstring(L, 2, &b_len);

    if (a_len != b_len) {
        lua_pushboolean(L, 0);
        return 1;
    }

    // XOR-accumulate over the full length. `volatile` on the
    // accumulator and the loop bound discourages the compiler from
    // rewriting the loop into a short-circuiting memcmp when it
    // proves a_len > 0 etc.
    volatile unsigned char diff = 0;
    volatile size_t n = a_len;
    for (size_t i = 0; i < n; ++i) {
        diff |= static_cast<unsigned char>(a[i] ^ b[i]);
    }
    lua_pushboolean(L, diff == 0 ? 1 : 0);
    return 1;
}

// ADC §2.4 unescape: '\s' -> space, '\n' -> newline, '\\' -> '\'.
// The spec leaves OTHER `\x` sequences UNDEFINED, and the legacy
// implementation silently dropped both bytes - a data-corruption /
// display-impersonation hazard (luadch-ng#315): an attacker could
// register a nick like "admin\q" which rendered as "admin", and any
// chat text with an unknown escape was silently mangled, breaking
// plugin keyword filters. We pick the no-data-loss interpretation:
// preserve unknown sequences as literal '\' + byte. Same shape for a
// trailing backslash at end-of-string (also previously dropped).
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
                    else if ('n' == *i)
                        out += '\n';
                    else if ('\\' == *i)
                        out += '\\';
                    else
                    {
                        // #315: unknown escape, preserve both bytes
                        out += '\\';
                        out += *i;
                    }
                }
                else
                {
                    // #315: trailing backslash, preserve literal
                    out += '\\';
                }
                break;
            default: out += *i;
        }
    }
    lua_pushlstring(L, out.c_str(), out.length());
    return 1;
}

/*
 * pbkdf2_sha256(password, salt, iterations, dklen) -> derived key (raw bytes)
 *
 * PBKDF2-HMAC-SHA256 via OpenSSL. The pure-Lua PBKDF2 in
 * core/backup_archive.lua is correct but ~tens of seconds at 200k
 * iterations - far too slow for the single-threaded hub, which would freeze
 * for the whole backup. This C path derives the SAME key (PBKDF2 is
 * deterministic) in ~1ms, so the backup passphrase keeps a strong iteration
 * count without stalling the loop. The Lua impl stays as the standalone /
 * self-test fallback and cross-checks against this one at load.
 */
int pbkdf2_sha256(lua_State* L)
{
    ERR_clear_error();
    size_t pw_len, salt_len;
    const char* pw   = luaL_checklstring(L, 1, &pw_len);
    const char* salt = luaL_checklstring(L, 2, &salt_len);
    if (pw_len > INT_MAX || salt_len > INT_MAX)
    {
        return luaL_error(L, "pbkdf2_sha256: password/salt too large");
    }
    lua_Integer iters = luaL_checkinteger(L, 3);
    lua_Integer dklen = luaL_checkinteger(L, 4);
    if (iters < 1 || iters > 100000000)
    {
        return luaL_error(L, "pbkdf2_sha256: iterations out of range (1..100000000)");
    }
    if (dklen < 1 || dklen > 1024)
    {
        return luaL_error(L, "pbkdf2_sha256: dklen out of range (1..1024)");
    }
    unsigned char out[1024];
    if (PKCS5_PBKDF2_HMAC(pw, (int)pw_len,
                          (const unsigned char *)salt, (int)salt_len,
                          (int)iters, EVP_sha256(), (int)dklen, out) != 1)
    {
        return luaL_error(L, "pbkdf2_sha256: PKCS5_PBKDF2_HMAC failed");
    }
    lua_pushlstring(L, (const char *)out, (size_t)dklen);
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
    {"pbkdf2_sha256", pbkdf2_sha256},
    {"gen_self_signed_cert", gen_self_signed_cert},
    {"cert_fingerprint_sha256", cert_fingerprint_sha256},
    {"constant_time_eq", constant_time_eq},
    {NULL, NULL}
};

extern "C" int luaopen_adclib(lua_State* L)
{
    luaL_newlib(L, adclib);
    return 1;
}

