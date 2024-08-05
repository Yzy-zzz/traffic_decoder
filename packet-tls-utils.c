#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "stream_base.h"
#include "packet-tls-utils.h"


//<-------------------------- 一些inline函数实现 -------------------------->
static inline int ssl_hmac_init(SSL_HMAC *md, int algo) {
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

static inline int ssl_hmac_setkey(SSL_HMAC *md, const void *key, int len) {
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

static inline int ssl_hmac_reset(SSL_HMAC *md) {
    gcry_md_reset(*md);
    return 0;
}

static inline void ssl_hmac_update(SSL_HMAC *md, const void *data, int len) {
    gcry_md_write(*(md), data, len);
}
static inline void ssl_hmac_final(SSL_HMAC *md, guchar *data, guint *datalen) {
    int algo;
    guint len;

    algo = gcry_md_get_algo(*(md));
    len = gcry_md_get_algo_dlen(algo);
    // DISSECTOR_ASSERT(len <= *datalen);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen = len;
}
static inline void ssl_hmac_cleanup(SSL_HMAC *md) { gcry_md_close(*(md)); }
int ssl_data_alloc(StringInfo *str, size_t len) {
    str->data = (guchar *)malloc(len);
    /* the allocator can return a null pointer for a size equal to 0,
     * and that must be allowed */
    if (len > 0 && !str->data)
        return -1;
    str->data_len = (guint)len;
    return 0;
}
static inline int
ssl_md_init(SSL_MD* md, int algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;
    err = gcry_md_open(md,algo, 0);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        printf("ssl_md_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}
static inline void
ssl_md_update(SSL_MD* md, guchar* data, int len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_md_final(SSL_MD* md, guchar* data, guint* datalen)
{
    int algo;
    int len;
    algo = gcry_md_get_algo (*(md));
    len = gcry_md_get_algo_dlen (algo);
    memcpy(data, gcry_md_read(*(md),  algo), len);
    *datalen = len;
}
static inline void
ssl_md_cleanup(SSL_MD* md)
{
    gcry_md_close(*(md));
}

static inline void
ssl_md_reset(SSL_MD* md)
{
    gcry_md_reset(*md);
}

static inline void
ssl_sha_init(SSL_SHA_CTX* md)
{
    gcry_md_open(md,GCRY_MD_SHA1, 0);
}
static inline void
ssl_sha_update(SSL_SHA_CTX* md, guchar* data, int len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_sha_final(guchar* buf, SSL_SHA_CTX* md)
{
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_SHA1),
           gcry_md_get_algo_dlen(GCRY_MD_SHA1));
}

static inline void
ssl_sha_reset(SSL_SHA_CTX* md)
{
    gcry_md_reset(*md);
}

static inline void
ssl_sha_cleanup(SSL_SHA_CTX* md)
{
    gcry_md_close(*(md));
}

static inline int
ssl_md5_init(SSL_MD5_CTX* md)
{
    return gcry_md_open(md,GCRY_MD_MD5, 0);
}
static inline void
ssl_md5_update(SSL_MD5_CTX* md, guchar* data, int len)
{
    gcry_md_write(*(md), data, len);
}
static inline void
ssl_md5_final(guchar* buf, SSL_MD5_CTX* md)
{
    memcpy(buf, gcry_md_read(*(md),  GCRY_MD_MD5),
           gcry_md_get_algo_dlen(GCRY_MD_MD5));
}

static inline void
ssl_md5_reset(SSL_MD5_CTX* md)
{
    gcry_md_reset(*md);
}

static inline void
ssl_md5_cleanup(SSL_MD5_CTX* md)
{
    gcry_md_close(*(md));
}
/* Pointer routines to put items out in a particular byte order.
 * These will work regardless of the byte alignment of the pointer.
 */
static inline void phton16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v >> 0);
}

static inline void phton32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v >> 0);
}

static inline void phton64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 56);
    p[1] = (uint8_t)(v >> 48);
    p[2] = (uint8_t)(v >> 40);
    p[3] = (uint8_t)(v >> 32);
    p[4] = (uint8_t)(v >> 24);
    p[5] = (uint8_t)(v >> 16);
    p[6] = (uint8_t)(v >> 8);
    p[7] = (uint8_t)(v >> 0);
}

static inline void phtole32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

static inline void phtole64(uint8_t *p, uint64_t v) {
    p[0] = (uint8_t)(v >> 0);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
    p[4] = (uint8_t)(v >> 32);
    p[5] = (uint8_t)(v >> 40);
    p[6] = (uint8_t)(v >> 48);
    p[7] = (uint8_t)(v >> 56);
}

//<-------------------------- 主要函数实现 -------------------------->



//<-------------------------- 主要函数实现 -------------------------->
/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
static gboolean
prf(SslDecryptSession *ssl, StringInfo *secret, const char *usage,
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
static bool tls12_prf(int md, StringInfo *secret, const char *usage,
                      StringInfo *rnd1, StringInfo *rnd2, StringInfo *out,
                      guint out_len) {
    StringInfo label_seed;
    int success;
    size_t usage_len, rnd2_len;
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    usage_len = strlen(usage);
    if (ssl_data_alloc(&label_seed, usage_len + rnd1->data_len + rnd2_len) <
        0) {
        printf("tls12_prf: can't allocate label_seed\n");
        return false;
    }
    memcpy(label_seed.data, usage, usage_len);
    memcpy(label_seed.data + usage_len, rnd1->data, rnd1->data_len);
    if (rnd2_len > 0)
        memcpy(label_seed.data + usage_len + rnd1->data_len, rnd2->data,
               rnd2->data_len);

    printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n",
           gcry_md_algo_name(md), secret->data_len, label_seed.data_len);

    ssl_print_data("tls12_prf: secret", secret->data, secret->data_len);
    ssl_print_data("tls12_prf: seed", label_seed.data, label_seed.data_len);

    ssl_data_alloc(out, out_len);
    success = tls_hash(secret, &label_seed, md, out, out_len);
    free(label_seed.data);
    if (success != -1) {
        ssl_print_data("PRF out", out->data, out->data_len);
        return true;
    }
    return false;
}
static int tls_hash(StringInfo *secret, StringInfo *seed, int md,
                    StringInfo *out, UINT32 out_len) {
    /* RFC 2246 5. HMAC and the pseudorandom function
     * '+' denotes concatenation.
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) + ...
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i - 1))
     */
    UCHAR *ptr;
    UINT32 left, tocpy;
    UCHAR *A;
    unsigned char _A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
    UINT32 A_l, tmp_l;
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

static int tls12_handshake_hash(StringInfo* handshake_data, int md, StringInfo* out)
{
    SSL_MD  mc;
    guint8 tmp[48];
    guint  len;
    ssl_md_init(&mc, md);
    printf("tls12_handshake_hash: ssl_md_update\n");
    ssl_md_update(&mc, handshake_data->data, handshake_data->data_len);
    printf("tls12_handshake_hash: ssl_md_final\n");
    ssl_md_final(&mc, tmp, &len);
    //输出len
    printf("tls12_handshake_hash: len %d\n", len);
    ssl_md_cleanup(&mc);

    if (ssl_data_alloc(out, len) < 0)
        return -1;
    memcpy(out->data, tmp, len);
    return 0;
}