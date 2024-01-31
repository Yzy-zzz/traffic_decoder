#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gcrypt.h>
#include <ctype.h>
#include "my_typedef.h"

int hexCharToInt(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

//16进制转换为字符串
unsigned char* convertHexStringToUCharArray(const char* hexStr) {
    size_t len = strlen(hexStr);
    size_t arraySize = len / 2;
    unsigned char *bytes = (unsigned char*)malloc(arraySize);

    for (size_t i = 0; i < len; i += 2) {
        bytes[i / 2] = (hexCharToInt(hexStr[i]) << 4) | hexCharToInt(hexStr[i + 1]);
    }

    return bytes;
}


static inline gint ssl_hmac_init(SSL_HMAC* md, gint algo)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;
    err = gcry_md_open(md,algo, GCRY_MD_FLAG_HMAC);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        // ssl_debug_printf("ssl_hmac_init(): gcry_md_open failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}

static inline gint ssl_hmac_setkey(SSL_HMAC* md, const void * key, gint len)
{
    gcry_error_t  err;
    const char   *err_str, *err_src;

    err = gcry_md_setkey (*(md), key, len);
    if (err != 0) {
        err_str = gcry_strerror(err);
        err_src = gcry_strsource(err);
        // ssl_debug_printf("ssl_hmac_setkey(): gcry_md_setkey failed %s/%s", err_str, err_src);
        return -1;
    }
    return 0;
}

static inline gint ssl_hmac_reset(SSL_HMAC* md)
{
    gcry_md_reset(*md);
    return 0;
}

static inline void ssl_hmac_update(SSL_HMAC* md, const void* data, gint len)
{
    gcry_md_write(*(md), data, len);
}
static inline void ssl_hmac_final(SSL_HMAC* md, guchar* data, guint* datalen)
{
    gint  algo;
    guint len;

    algo = gcry_md_get_algo (*(md));
    len  = gcry_md_get_algo_dlen(algo);
    // DISSECTOR_ASSERT(len <= *datalen);
    memcpy(data, gcry_md_read(*(md), algo), len);
    *datalen = len;
}
static inline void ssl_hmac_cleanup(SSL_HMAC* md)
{
    gcry_md_close(*(md));
}
gint ssl_data_alloc(StringInfo* str, size_t len)
{
    str->data = (guchar *)malloc(len);
    /* the allocator can return a null pointer for a size equal to 0,
     * and that must be allowed */
    if (len > 0 && !str->data)
        return -1;
    str->data_len = (guint) len;
    return 0;
}

static const SslDigestAlgo *ssl_cipher_suite_dig(const SslCipherSuite *cs) {
    return &digests[cs->dig - DIG_MD5];
}

void ssl_print_data(const char* name, const guchar* data, size_t len)
{
    static FILE* ssl_debug_file=fopen("ssl_debug_file.txt","w");
    size_t i, j, k;
    if (!ssl_debug_file)
        return;
    fprintf(ssl_debug_file,"%s[%d]:\n",name, (int) len);
    for (i=0; i<len; i+=16) {
        fprintf(ssl_debug_file,"| ");
        for (j=i, k=0; k<16 && j<len; ++j, ++k)
            fprintf(ssl_debug_file,"%.2x ",data[j]);
        for (; k<16; ++k)
            fprintf(ssl_debug_file,"   ");
        fputc('|', ssl_debug_file);
        for (j=i, k=0; k<16 && j<len; ++j, ++k) {
            guchar c = data[j];
            if (!isprint(c) || (c=='\t')) c = '.';
            fputc(c, ssl_debug_file);
        }
        for (; k<16; ++k)
            fputc(' ', ssl_debug_file);
        fprintf(ssl_debug_file,"|\n");
    }

}
void ssl_data_set(StringInfo* str, const guchar* data, guint len)
{
    // DISSECTOR_ASSERT(data);
    memcpy(str->data, data, len);
    str->data_len = len;
}

/*根据数据包中的值，确定套件信息
    {0xC02F,KEX_ECDHE_RSA,ENC_AES,DIG_SHA256, MODE_GCM},   
     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 
*/
const SslCipherSuite *ssl_find_cipher(int num)
{
    const SslCipherSuite *c;
    for(c=cipher_suites;c->number!=-1;c++){
        if(c->number==num){
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

// tls12_prf函数实现
static bool tls12_prf(gint md, StringInfo *secret, const char *usage,
                      StringInfo *rnd1, StringInfo *rnd2, StringInfo *out,
                      guint out_len) {
    StringInfo label_seed;
    int success;
    size_t usage_len, rnd2_len;
    rnd2_len = rnd2 ? rnd2->data_len : 0;

    usage_len = strlen(usage);
    if (ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2_len) < 0) {
        printf("tls12_prf: can't allocate label_seed\n");
        return false;
    }    
    memcpy(label_seed.data, usage, usage_len);
    memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
    if (rnd2_len > 0)
        memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);

    printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n",
           gcry_md_algo_name(md), secret->data_len, label_seed.data_len);

    ssl_print_data("tls12_prf: secret", secret->data, secret->data_len);
    ssl_print_data("tls12_prf: seed", label_seed.data, label_seed.data_len);

    ssl_data_alloc(out, out_len);
    success = tls_hash(secret, &label_seed, md, out, out_len);
    free(label_seed.data);
    if(success!=-1){
        ssl_print_data("PRF out", out->data,out->data_len);
        return true;
    }
    return false;
}

/* out_len is the wanted output length for the pseudorandom function.
 * Ensure that ssl->cipher_suite is set. */
static bool prf(const SslCipherSuite *cs, StringInfo *secret, const char *usage,
                StringInfo *rnd1, StringInfo *rnd2, StringInfo *out,
                guint out_len) {
    // switch (ssl->session.version) {
    // case SSLV3_VERSION:
    //     return ssl3_prf(secret, usage, rnd1, rnd2, out, out_len);

    // case TLSV1_VERSION:
    // case TLSV1DOT1_VERSION:
    // case DTLSV1DOT0_VERSION:
    // case DTLSV1DOT0_OPENSSL_VERSION:
    //     return tls_prf(secret, usage, rnd1, rnd2, out, out_len);

    // default: /* TLSv1.2 */
    // switch (ssl->cipher_suite->dig) {
    switch (cs->dig) {
    case DIG_SM3:
#if GCRYPT_VERSION_NUMBER >= 0x010900
        return tls12_prf(GCRY_MD_SM3, secret, usage, rnd1, rnd2, out, out_len);
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

/*
    根据套件，算出用来生成秘钥的一些信息
*/
int generate_key_material(const SslCipherSuite *cipher_suite, StringInfo *secret, const char *usage,
                StringInfo *rnd1, StringInfo *rnd2, StringInfo *out){

    int        needed;
    int       cipher_algo = -1;
    guint       encr_key_len, write_iv_len = 0;
    bool    is_export_cipher;
    unsigned char     *ptr, *c_iv = NULL, *s_iv = NULL;
    unsigned char      _key_c[MAX_KEY_SIZE],_key_s[MAX_KEY_SIZE];
    unsigned char     *c_wk = NULL, *s_wk = NULL, *c_mk = NULL, *s_mk = NULL;

    if (cipher_suite->enc != ENC_NULL) {
        const char *cipher_name = ciphers[cipher_suite->enc-ENC_START];
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
    } else if (cipher_suite->mode == MODE_GCM || cipher_suite->mode == MODE_CCM || cipher_suite->mode == MODE_CCM_8) {
        /* account for a four-byte salt for client and server side (from
         * client_write_IV and server_write_IV), see GCMNonce (RFC 5288) */
        write_iv_len = 4;
    } else if (cipher_suite->mode == MODE_POLY1305) {
        /* RFC 7905: SecurityParameters.fixed_iv_length is twelve bytes */
        write_iv_len = 12;
    }

    /* Compute the key block. First figure out how much data we need */
    needed = ssl_cipher_suite_dig(cipher_suite)->len*2;     /* MAC key  */
    needed += 2 * encr_key_len;                             /* encryption key */
    needed += 2 * write_iv_len;                             /* write IV */
    
    // printf("cipher_name:%s\n",ciphers[cipher_suite->enc-ENC_START]);
    // printf("cipher_algo:%d\n",cipher_algo);
    // printf("ecry_key_len:%d\n",encr_key_len);
    // printf("write_iv_len:%d\n",write_iv_len);

    printf("need out_len:%d\n",needed);

    // return needed;
    // key_block.data = (guchar *)malloc(needed);
    /* ssl_debug_printf("%s sess key generation\n", G_STRFUNC);*/

    //对于key_expansion 先server_random再 client_random
    // prf(cs, secret, usage, rnd2, rnd1, out, out_len);

    if (!prf(cipher_suite, secret, usage, rnd1, rnd2, out, needed)) {
        // ssl_debug_printf("%s can't generate key_block\n", G_STRFUNC);
        // goto fail;
    }

    ptr=out->data;
    /* client/server write MAC key (for non-AEAD ciphers) */
    if (cipher_suite->mode == MODE_STREAM || cipher_suite->mode == MODE_CBC) {
        c_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
        s_mk=ptr; ptr+=ssl_cipher_suite_dig(cipher_suite)->len;
    }
    /* client/server write encryption key */
    c_wk=ptr; ptr += encr_key_len;
    s_wk=ptr; ptr += encr_key_len;
    /* client/server write IV (used as IV (for CBC) or salt (for AEAD)) */
    if (write_iv_len > 0) {
        c_iv=ptr; ptr += write_iv_len;
        s_iv=ptr; /* ptr += write_iv_len; */
    }
    // ssl_print_string("key expansion", &key_block);

    if(is_export_cipher){
            StringInfo key_c, key_s, k;
            key_c.data = _key_c;
            key_s.data = _key_s;

            k.data = c_wk;
            k.data_len = encr_key_len;
            // ssl_debug_printf("%s PRF(key_c)\n", G_STRFUNC);
            if (!prf(cipher_suite, &k, "client write key",
                    rnd1,
                    rnd2, &key_c, sizeof(_key_c))) {
                // ssl_debug_printf("%s can't generate tll31 server key \n", G_STRFUNC);
                // goto fail;
            }
            c_wk=_key_c;

            k.data = s_wk;
            k.data_len = encr_key_len;
            // ssl_debug_printf("%s PRF(key_s)\n", G_STRFUNC);
            if (!prf(cipher_suite, &k, "server write key",
                    rnd1,
                    rnd2, &key_s, sizeof(_key_s))) {
                // ssl_debug_printf("%s can't generate tll31 client key \n", G_STRFUNC);
                // goto fail;
            }
            s_wk=_key_s;
        }

        /* show key material info */
    if (c_mk != NULL) {
        size_t len = ssl_cipher_suite_dig(cipher_suite)->len;
        ssl_print_data("Client MAC key",c_mk,len);
        ssl_print_data("Server MAC key",s_mk,len);
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

