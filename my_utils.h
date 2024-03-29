#include "my_typedef.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int hexCharToInt(char c) {
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

// 16进制转换为字符串
unsigned char *convertHexStringToUCharArray(const char *hexStr) {
    size_t len = strlen(hexStr);
    size_t arraySize = len / 2;
    unsigned char *bytes = (unsigned char *)malloc(arraySize);

    for (size_t i = 0; i < len; i += 2) {
        bytes[i / 2] =
            (hexCharToInt(hexStr[i]) << 4) | hexCharToInt(hexStr[i + 1]);
    }

    return bytes;
}

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

static const SslDigestAlgo *ssl_cipher_suite_dig(const SslCipherSuite *cs) {
    return &digests[cs->dig - DIG_MD5];
}

void ssl_print_data(const char *name, const guchar *data, size_t len) {
    static FILE *ssl_debug_file = fopen("ssl_debug_file.txt", "w");
    size_t i, j, k;
    if (!ssl_debug_file)
        return;
    fprintf(ssl_debug_file, "%s[%d]:\n", name, (int)len);
    for (i = 0; i < len; i += 16) {
        fprintf(ssl_debug_file, "| ");
        for (j = i, k = 0; k < 16 && j < len; ++j, ++k)
            fprintf(ssl_debug_file, "%.2x ", data[j]);
        for (; k < 16; ++k)
            fprintf(ssl_debug_file, "   ");
        fputc('|', ssl_debug_file);
        for (j = i, k = 0; k < 16 && j < len; ++j, ++k) {
            guchar c = data[j];
            if (!isprint(c) || (c == '\t'))
                c = '.';
            fputc(c, ssl_debug_file);
        }
        for (; k < 16; ++k)
            fputc(' ', ssl_debug_file);
        fprintf(ssl_debug_file, "|\n");
    }
}
void ssl_data_set(StringInfo *str, const guchar *data, guint len) {
    // DISSECTOR_ASSERT(data);
    memcpy(str->data, data, len);
    str->data_len = len;
}

/*根据数据包中的值，确定套件信息
    {0xC02F,KEX_ECDHE_RSA,ENC_AES,DIG_SHA256, MODE_GCM},
     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
*/
const SslCipherSuite *ssl_find_cipher(int num) {
    const SslCipherSuite *c;
    for (c = cipher_suites; c->number != -1; c++) {
        if (c->number == num) {
            return c;
        }
    }
    return NULL;
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
static inline void
ssl_sha_init(SSL_SHA_CTX* md)
{
    gcry_md_open(md,GCRY_MD_SHA1, 0);
}
static inline void
ssl_sha_update(SSL_SHA_CTX* md, guchar* data, gint len)
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

static inline gint
ssl_md5_init(SSL_MD5_CTX* md)
{
    return gcry_md_open(md,GCRY_MD_MD5, 0);
}
static inline void
ssl_md5_update(SSL_MD5_CTX* md, guchar* data, gint len)
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

static gboolean
ssl3_prf(StringInfo* secret, const char* usage,
         StringInfo* rnd1, StringInfo* rnd2, StringInfo* out, guint out_len)
{
    SSL_MD5_CTX  md5;
    SSL_SHA_CTX  sha;
    guint        off;
    gint         i = 0,j;
    guint8       buf[20];

    ssl_sha_init(&sha);
    ssl_md5_init(&md5);
    for (off = 0; off < out_len; off += 16) {
        guchar outbuf[16];
        i++;

        // ssl_debug_printf("ssl3_prf: sha1_hash(%d)\n",i);
        /* A, BB, CCC,  ... */
        for(j=0;j<i;j++){
            buf[j]=64+i;
        }

        ssl_sha_update(&sha,buf,i);
        ssl_sha_update(&sha,secret->data,secret->data_len);

        if(!strcmp(usage,"client write key") || !strcmp(usage,"server write key")){
            if (rnd2)
                ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
        }
        else{
            ssl_sha_update(&sha,rnd1->data,rnd1->data_len);
            if (rnd2)
                ssl_sha_update(&sha,rnd2->data,rnd2->data_len);
        }

        ssl_sha_final(buf,&sha);
        ssl_sha_reset(&sha);

        // ssl_debug_printf("ssl3_prf: md5_hash(%d) datalen %d\n",i,secret->data_len);
        ssl_md5_update(&md5,secret->data,secret->data_len);
        ssl_md5_update(&md5,buf,20);
        ssl_md5_final(outbuf,&md5);
        ssl_md5_reset(&md5);

        memcpy(out->data + off, outbuf, MIN(out_len - off, 16));
    }
    ssl_sha_cleanup(&sha);
    ssl_md5_cleanup(&md5);
    out->data_len = out_len;

    return true;
}

/*用于tls1.2下面的版本*/
static gboolean tls_prf(StringInfo *secret, const char *usage, StringInfo *rnd1,
                        StringInfo *rnd2, StringInfo *out, guint out_len) {
    StringInfo seed, sha_out, md5_out;
    guint8 *ptr;
    StringInfo s1, s2;
    guint i, s_l;
    size_t usage_len, rnd2_len;
    gboolean success = false;
    usage_len = strlen(usage);
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    /* initalize buffer for sha, md5 random seed*/
    if (ssl_data_alloc(&sha_out, out_len > 20 ? out_len : 20) < 0) {
        printf("tls_prf: can't allocate sha out\n");
        return false;
    }
    if (ssl_data_alloc(&md5_out, out_len > 20 ? out_len : 16) < 0) {
        printf("tls_prf: can't allocate md5 out\n");
        goto free_sha;
    }
    if (ssl_data_alloc(&seed, usage_len + rnd1->data_len + rnd2_len) < 0) {
        printf("tls_prf: can't allocate rnd %d\n",
               (int)(usage_len + rnd1->data_len + rnd2_len));
        goto free_md5;
    }

    ptr = seed.data;
    memcpy(ptr, usage, usage_len);
    ptr += usage_len;
    memcpy(ptr, rnd1->data, rnd1->data_len);
    if (rnd2_len > 0) {
        ptr += rnd1->data_len;
        memcpy(ptr, rnd2->data, rnd2->data_len);
        /*ptr+=rnd2->data_len;*/
    }

    /* initalize buffer for client/server seeds*/
    s_l = secret->data_len / 2 + secret->data_len % 2;
    if (ssl_data_alloc(&s1, s_l) < 0) {
        printf("tls_prf: can't allocate secret %d\n", s_l);
        goto free_seed;
    }
    if (ssl_data_alloc(&s2, s_l) < 0) {
        printf("tls_prf: can't allocate secret(2) %d\n", s_l);
        goto free_s1;
    }

    memcpy(s1.data, secret->data, s_l);
    memcpy(s2.data, secret->data + (secret->data_len - s_l), s_l);

    printf("tls_prf: tls_hash(md5 secret_len %d seed_len %d )\n", s1.data_len,
           seed.data_len);
    if (tls_hash(&s1, &seed, gcry_md_map_name("MD5"), &md5_out, out_len) != 0)
        goto free_s2;
    printf("tls_prf: tls_hash(sha)\n");
    if (tls_hash(&s2, &seed, gcry_md_map_name("SHA1"), &sha_out, out_len) != 0)
        goto free_s2;

    for (i = 0; i < out_len; i++)
        out->data[i] = md5_out.data[i] ^ sha_out.data[i];
    /* success, now store the new meaningful data length */
    out->data_len = out_len;
    success = true;

    ssl_print_data("PRF out", out->data, out->data_len);
free_s2:
    free(s2.data);
free_s1:
    free(s1.data);
free_seed:
    free(seed.data);
free_md5:
    free(md5_out.data);
free_sha:
    free(sha_out.data);
    return success;
}
// tls12_prf函数实现
static bool tls12_prf(gint md, StringInfo *secret, const char *usage,
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

/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
static bool prf(const SslCipherSuite *cs, StringInfo *secret, const char *usage,
                StringInfo *rnd1, StringInfo *rnd2, StringInfo *out,
                guint out_len) {
    
    // 待测试补充 目前0x303代表tls1.2类型
    unsigned short version = 0x303;

    switch (version) {
    case SSLV3_VERSION:
        return ssl3_prf(secret, usage, rnd1, rnd2, out, out_len);

    case TLSV1_VERSION:
    case TLSV1DOT1_VERSION:
    case DTLSV1DOT0_VERSION:
    case DTLSV1DOT0_OPENSSL_VERSION:
        return tls_prf(secret, usage, rnd1, rnd2, out, out_len);

    default: /* TLSv1.2 */
        switch (cs->dig) {
        case DIG_SM3:
#if GCRYPT_VERSION_NUMBER >= 0x010900
            return tls12_prf(GCRY_MD_SM3, secret, usage, rnd1, rnd2, out,
                             out_len);
#else
            return false;
#endif
        case DIG_SHA384:
            return tls12_prf(GCRY_MD_SHA384, secret, usage, rnd1, rnd2, out,
                             out_len);
        default:
            return tls12_prf(GCRY_MD_SHA256, secret, usage, rnd1, rnd2, out,
                             out_len);
        }
    }
}

/*
    根据套件，算出用来生成秘钥的一些信息
*/
int generate_key_material(const SslCipherSuite *cipher_suite,
                          StringInfo *secret, const char *usage,
                          StringInfo *rnd1, StringInfo *rnd2, StringInfo *out) {

    int needed;
    int cipher_algo = -1;
    guint encr_key_len, write_iv_len = 0;
    bool is_export_cipher;
    unsigned char *ptr, *c_iv = NULL, *s_iv = NULL;
    unsigned char _key_c[MAX_KEY_SIZE], _key_s[MAX_KEY_SIZE];
    unsigned char *c_wk = NULL, *s_wk = NULL, *c_mk = NULL, *s_mk = NULL;

    if (cipher_suite->enc != ENC_NULL) {
        const char *cipher_name = ciphers[cipher_suite->enc - ENC_START];
        // ssl_debug_printf("%s CIPHER: %s\n", G_STRFUNC, cipher_name);
        cipher_algo = gcry_cipher_map_name(cipher_name);
        if (cipher_algo == 0) {
            printf("can't find cipher %s\n", cipher_name);
            return -1;
        }
    }

    /* Export ciphers consume less material from the key block. */
    encr_key_len = ssl_get_cipher_export_keymat_size(cipher_suite->number);
    is_export_cipher = encr_key_len > 0;
    if (!is_export_cipher && cipher_suite->enc != ENC_NULL) {
        encr_key_len = (guint)gcry_cipher_get_algo_keylen(cipher_algo);
    }

    if (cipher_suite->mode == MODE_CBC) {
        write_iv_len = (guint)gcry_cipher_get_algo_blklen(cipher_algo);
    } else if (cipher_suite->mode == MODE_GCM ||
               cipher_suite->mode == MODE_CCM ||
               cipher_suite->mode == MODE_CCM_8) {
        /* account for a four-byte salt for client and server side (from
         * client_write_IV and server_write_IV), see GCMNonce (RFC 5288) */
        write_iv_len = 4;
    } else if (cipher_suite->mode == MODE_POLY1305) {
        /* RFC 7905: SecurityParameters.fixed_iv_length is twelve bytes */
        write_iv_len = 12;
    }

    /* Compute the key block. First figure out how much data we need */
    needed = ssl_cipher_suite_dig(cipher_suite)->len * 2; /* MAC key  */
    needed += 2 * encr_key_len;                           /* encryption key */
    needed += 2 * write_iv_len;                           /* write IV */

    // printf("cipher_name:%s\n",ciphers[cipher_suite->enc-ENC_START]);
    // printf("cipher_algo:%d\n",cipher_algo);
    // printf("ecry_key_len:%d\n",encr_key_len);
    // printf("write_iv_len:%d\n",write_iv_len);

    printf("need out_len:%d\n", needed);

    // return needed;
    // key_block.data = (guchar *)malloc(needed);
    /* ssl_debug_printf("%s sess key generation\n", G_STRFUNC);*/

    // 对于key_expansion 先server_random再 client_random
    //  prf(cs, secret, usage, rnd2, rnd1, out, out_len);

    // prf过程，用来生成会话秘钥
    if (!prf(cipher_suite, secret, usage, rnd1, rnd2, out, needed)) {
        // ssl_debug_printf("%s can't generate key_block\n", G_STRFUNC);
        // goto fail;
    }

    ptr = out->data;
    /* client/server write MAC key (for non-AEAD ciphers) */
    if (cipher_suite->mode == MODE_STREAM || cipher_suite->mode == MODE_CBC) {
        c_mk = ptr;
        ptr += ssl_cipher_suite_dig(cipher_suite)->len;
        s_mk = ptr;
        ptr += ssl_cipher_suite_dig(cipher_suite)->len;
    }
    /* client/server write encryption key */
    c_wk = ptr;
    ptr += encr_key_len;
    s_wk = ptr;
    ptr += encr_key_len;
    /* client/server write IV (used as IV (for CBC) or salt (for AEAD)) */
    if (write_iv_len > 0) {
        c_iv = ptr;
        ptr += write_iv_len;
        s_iv = ptr; /* ptr += write_iv_len; */
    }
    // ssl_print_string("key expansion", &key_block);

    if (is_export_cipher) {
        StringInfo key_c, key_s, k;
        key_c.data = _key_c;
        key_s.data = _key_s;

        k.data = c_wk;
        k.data_len = encr_key_len;
        // ssl_debug_printf("%s PRF(key_c)\n", G_STRFUNC);
        if (!prf(cipher_suite, &k, "client write key", rnd1, rnd2, &key_c,
                 sizeof(_key_c))) {
            // ssl_debug_printf("%s can't generate tll31 server key \n",
            // G_STRFUNC); goto fail;
        }
        c_wk = _key_c;

        k.data = s_wk;
        k.data_len = encr_key_len;
        // ssl_debug_printf("%s PRF(key_s)\n", G_STRFUNC);
        if (!prf(cipher_suite, &k, "server write key", rnd1, rnd2, &key_s,
                 sizeof(_key_s))) {
            // ssl_debug_printf("%s can't generate tll31 client key \n",
            // G_STRFUNC); goto fail;
        }
        s_wk = _key_s;
    }

    /* show key material info */
    if (c_mk != NULL) {
        size_t len = ssl_cipher_suite_dig(cipher_suite)->len;
        ssl_print_data("Client MAC key", c_mk, len);
        ssl_print_data("Server MAC key", s_mk, len);
    }
    ssl_print_data("Client Write key", c_wk, encr_key_len);
    ssl_print_data("Server Write key", s_wk, encr_key_len);
    /* used as IV for CBC mode and the AEAD implicit nonce (salt) */
    if (write_iv_len > 0) {
        ssl_print_data("Client Write IV", c_iv, write_iv_len);
        ssl_print_data("Server Write IV", s_iv, write_iv_len);
    }

    return 1;
}
