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
void
ssl_print_data(const char* name, const guchar* data, size_t len)
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

static void ssl_set_cipher(SslDecryptSession *ssl, guint16 cipher)
{
    /* store selected cipher suite for decryption */
    // ssl->session.cipher = cipher;

    const SslCipherSuite *cs = ssl_find_cipher(cipher);
    if (!cs) {
        ssl->cipher_suite = NULL;
        ssl->state &= ~SSL_CIPHER;
        // ssl_debug_printf("%s can't find cipher suite 0x%04X\n", G_STRFUNC, cipher);
    // } else if (ssl->session.version == SSLV3_VERSION && !(cs->dig == DIG_MD5 || cs->dig == DIG_SHA)) {
        /* A malicious packet capture contains a SSL 3.0 session using a TLS 1.2
         * cipher suite that uses for example MACAlgorithm SHA256. Reject that
         * to avoid a potential buffer overflow in ssl3_check_mac. */
        ssl->cipher_suite = NULL;
        ssl->state &= ~SSL_CIPHER;
        // ssl_debug_printf("%s invalid SSL 3.0 cipher suite 0x%04X\n", G_STRFUNC, cipher);
    } else {
        /* Cipher found, save this for the delayed decoder init */
        ssl->cipher_suite = cs;
        ssl->state |= SSL_CIPHER;
        // ssl_debug_printf("%s found CIPHER 0x%04X %s -> state 0x%02X\n", G_STRFUNC, cipher,
        //                  val_to_str_ext_const(cipher, &ssl_31_ciphersuite_ext, "unknown"),
        //                  ssl->state);
    }
}



// static SslDecoder*
// ssl_create_decoder(const SslCipherSuite *cipher_suite, gint cipher_algo,
//         gint compression, guint8 *mk, guint8 *sk, guint8 *iv, guint iv_length)
// {
//     SslDecoder *dec;
//     ssl_cipher_mode_t mode = cipher_suite->mode;

//     dec = wmem_new0(wmem_file_scope(), SslDecoder);
//     /* init mac buffer: mac storage is embedded into decoder struct to save a
//      memory allocation and waste samo more memory*/
//     dec->cipher_suite=cipher_suite;
//     dec->compression = compression;
//     if ((mode == MODE_STREAM && mk != NULL) || mode == MODE_CBC) {
//         // AEAD ciphers use no MAC key, but stream and block ciphers do. Note
//         // the special case for NULL ciphers, even if there is insufficieny
//         // keying material (including MAC key), we will can still create
//         // decoders since "decryption" is easy for such ciphers.
//         dec->mac_key.data = dec->_mac_key_or_write_iv;
//         ssl_data_set(&dec->mac_key, mk, ssl_cipher_suite_dig(cipher_suite)->len);
//     } else if (mode == MODE_GCM || mode == MODE_CCM || mode == MODE_CCM_8 || mode == MODE_POLY1305) {
//         // Input for the nonce, to be used with AEAD ciphers.
//         DISSECTOR_ASSERT(iv_length <= sizeof(dec->_mac_key_or_write_iv));
//         dec->write_iv.data = dec->_mac_key_or_write_iv;
//         ssl_data_set(&dec->write_iv, iv, iv_length);
//     }
//     dec->seq = 0;
//     dec->decomp = ssl_create_decompressor(compression);
//     wmem_register_callback(wmem_file_scope(), ssl_decoder_destroy_cb, dec);

//     if (ssl_cipher_init(&dec->evp,cipher_algo,sk,iv,cipher_suite->mode) < 0) {
//         ssl_debug_printf("%s: can't create cipher id:%d mode:%d\n", G_STRFUNC,
//             cipher_algo, cipher_suite->mode);
//         return NULL;
//     }

//     ssl_debug_printf("decoder initialized (digest len %d)\n", ssl_cipher_suite_dig(cipher_suite)->len);
//     return dec;
// }