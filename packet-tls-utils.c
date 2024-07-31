#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "packet-tls-utils.h"


//<-------------------------- 一些inline函数实现 -------------------------->
static inline gint ssl_hmac_init(SSL_HMAC *md, gint algo) {
    gcry_error_t err;
    const char *err_str, *err_src;
    err = gcry_md_open(md, algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        // ssl_debug_printf("ssl_hmac_init(): gcry_md_open failed %s/%s",
        // err_str, err_src);
        return -1;
    }
    return 0;
}

static inline gint ssl_hmac_setkey(SSL_HMAC *md, const void *key, gint len) {
    gcry_error_t err;
    const char *err_str, *err_src;

    err = gcry_md_setkey(*(md), key, len);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        // ssl_debug_printf("ssl_hmac_setkey(): gcry_md_setkey failed %s/%s",
        // err_str, err_src);
        return -1;
    }
    return 0;
}

static inline gint ssl_hmac_reset(SSL_HMAC *md) {
    gcry_md_reset(*md);
    return 0;
}

static inline void ssl_hmac_update(SSL_HMAC *md, const void *data, gint len) {
    gcry_md_write(*(md), data, len);
}
static inline void ssl_hmac_final(SSL_HMAC *md, guchar *data, guint *datalen) {
    gint algo;
    guint len;

    algo = gcry_md_get_algo(*(md));
    len = gcry_md_get_algo_dlen(algo);
    // DISSECTOR_ASSERT(len <= *datalen);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen = len;
}
static inline void ssl_hmac_cleanup(SSL_HMAC *md) { gcry_md_close(*(md)); }
gint ssl_data_alloc(StringInfo *str, size_t len) {
    str->data = (guchar *)malloc(len);
    /* the allocator can return a null pointer for a size equal to 0,
     * and that must be allowed */
    if (len > 0 && !str->data)
        return -1;
    str->data_len = (guint)len;
    return 0;
}


//<-------------------------- 主要函数实现 -------------------------->
/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
static gboolean
prf(SslDecryptSession *ssl, StringInfo *secret, const gchar *usage,
    StringInfo *rnd1, StringInfo *rnd2, StringInfo *out, guint out_len)
{
    switch (ssl->session.version) {
    case SSLV3_VERSION:
        return ssl3_prf(secret, usage, rnd1, rnd2, out, out_len);

    case TLSV1_VERSION:
    case TLSV1DOT1_VERSION:
    case DTLSV1DOT0_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
        return tls_prf(secret, usage, rnd1, rnd2, out, out_len);

    default: /* TLSv1.2 */
        switch (ssl->cipher_suite->dig) {
        case DIG_SM3:
#if GCRYPT_VERSION_NUMBER >= 0x010900
            return tls12_prf(GCRY_MD_SM3, secret, usage, rnd1, rnd2,
                             out, out_len);
#else
            return FALSE;
#endif
        case DIG_SHA384:
            return tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2,
                             out, out_len);
        default:
            return tls12_prf(GCRY_MD_SHA256, secret, usage, rnd1, rnd2,
                             out, out_len);
        }
    }
}

static int tls_hash(StringInfo *secret, StringInfo *seed, int md,
                    StringInfo *out, uint out_len) {
    /* RFC 2246 5. HMAC and the pseudorandom function
     * '+' denotes concatenation.
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) + ...
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i - 1))
     */
    u_char *ptr;
    uint left, tocpy;
    u_char *A;
    unsigned char _A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
    uint A_l, tmp_l;
    SSL_HMAC hm;

    ptr = out->data;
    left = out_len;

    // ssl_print_string("tls_hash: hash secret", secret);
    // ssl_print_string("tls_hash: hash seed", seed);
    /* A(0) = seed */
    A = seed->data;
    A_l = seed->data_len;

    if (ssl_hmac_init(&hm, md) != 0) {
        return -1;
    }
    while (left) {
        /* A(i) = HMAC_hash(secret, A(i-1)) */
        ssl_hmac_setkey(&hm, secret->data, secret->data_len);
        ssl_hmac_update(&hm, A, A_l);
        A_l = sizeof(_A); /* upper bound len for hash output */
        ssl_hmac_final(&hm, _A, &A_l);
        A = _A;

        /* HMAC_hash(secret, A(i) + seed) */
        ssl_hmac_reset(&hm);
        ssl_hmac_setkey(&hm, secret->data, secret->data_len);
        ssl_hmac_update(&hm, A, A_l);
        ssl_hmac_update(&hm, seed->data, seed->data_len);
        tmp_l = sizeof(tmp); /* upper bound len for hash output */
        ssl_hmac_final(&hm, tmp, &tmp_l);
        ssl_hmac_reset(&hm);

        /* ssl_hmac_final puts the actual digest output size in tmp_l */
        tocpy = left < tmp_l ? left : tmp_l;
        memcpy(ptr, tmp, tocpy);
        ptr += tocpy;
        left -= tocpy;
    }
    ssl_hmac_cleanup(&hm);
    out->data_len = out_len;

    // printf("out->data_len %d\n", out->data_len);
    // printf("out->data %s\n", out->data);
    ssl_print_data("hash out", out->data, out_len);
    return false;
}
