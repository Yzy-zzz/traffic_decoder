#ifndef __PACKET_TLS_UTILS_H__
#define __PACKET_TLS_UTILS_H__

#include <stdint.h>
#include <stdbool.h>
#include <gcrypt.h>
#include <ctype.h>


//<-------------------------- 字段定义 -------------------------->
#define DIGEST_MAX_SIZE 48
#define MAX_KEY_SIZE 32
#define SSL_MASTER_SECRET_LENGTH        48

#define SSL_HMAC gcry_md_hd_t
#define SSL_SHA_CTX gcry_md_hd_t
#define SSL_MD5_CTX gcry_md_hd_t
#define SSL_MD gcry_md_hd_t
#define SSL_CIPHER              (1<<2)
#define SSL_CIPHER_CTX gcry_cipher_hd_t

#define SSL_VER_UNKNOWN         0
#define SSLV2_VERSION           0x0002 /* not in record layer, SSL_CLIENT_SERVER from
                                          http://www-archive.mozilla.org/projects/security/pki/nss/ssl/draft02.html */
#define SSLV3_VERSION          0x300
#define TLSV1_VERSION          0x301
#define TLCPV1_VERSION         0x101
#define TLSV1DOT1_VERSION      0x302
#define TLSV1DOT2_VERSION      0x303
#define TLSV1DOT3_VERSION      0x304
#define DTLSV1DOT0_VERSION     0xfeff
#define DTLSV1DOT0_OPENSSL_VERSION 0x100
#define DTLSV1DOT2_VERSION     0xfefd
#define DTLSV1DOT3_VERSION     0xfefc



#define KEX_DHE_DSS     0x10
#define KEX_DHE_PSK     0x11
#define KEX_DHE_RSA     0x12
#define KEX_DH_ANON     0x13
#define KEX_DH_DSS      0x14
#define KEX_DH_RSA      0x15
#define KEX_ECDHE_ECDSA 0x16
#define KEX_ECDHE_PSK   0x17
#define KEX_ECDHE_RSA   0x18
#define KEX_ECDH_ANON   0x19
#define KEX_ECDH_ECDSA  0x1a
#define KEX_ECDH_RSA    0x1b
#define KEX_KRB5        0x1c
#define KEX_PSK         0x1d
#define KEX_RSA         0x1e
#define KEX_RSA_PSK     0x1f
#define KEX_SRP_SHA     0x20
#define KEX_SRP_SHA_DSS 0x21
#define KEX_SRP_SHA_RSA 0x22
#define KEX_IS_DH(n)    ((n) >= KEX_DHE_DSS && (n) <= KEX_ECDH_RSA)
#define KEX_TLS13       0x23
#define KEX_ECJPAKE     0x24

#define KEX_ECDHE_SM2   0x25
#define KEX_ECC_SM2     0x26
#define KEX_IBSDH_SM9   0x27
#define KEX_IBC_SM9     0x28

/* Order is significant, must match "ciphers" array in packet-tls-utils.c */

#define ENC_START       0x30
#define ENC_DES         0x30
#define ENC_3DES        0x31
#define ENC_RC4         0x32
#define ENC_RC2         0x33
#define ENC_IDEA        0x34
#define ENC_AES         0x35
#define ENC_AES256      0x36
#define ENC_CAMELLIA128 0x37
#define ENC_CAMELLIA256 0x38
#define ENC_SEED        0x39
#define ENC_CHACHA20    0x3A
#define ENC_SM1         0x3B
#define ENC_SM4         0x3C
#define ENC_NULL        0x3D


#define DIG_MD5         0x40
#define DIG_SHA         0x41
#define DIG_SHA256      0x42
#define DIG_SHA384      0x43
#define DIG_SM3         0x44
#define DIG_NA          0x45 /* Not Applicable */

#define MIN(a, b) ((a) < (b) ? (a) : (b))

//<-------------------------- 修复glib不能用 -------------------------->
//只好自己定义一下
typedef int gint;
typedef unsigned char guchar;
typedef unsigned char guint8;
typedef unsigned int guint;
typedef u_int64_t guint64;
typedef u_int32_t guint32;
typedef u_int16_t guint16;
typedef bool gboolean;

//<-------------------------- 结构体定义 -------------------------->

typedef struct _StringInfo {
    unsigned char  *data;      /* Backing storage which may be larger than data_len */
    int    data_len;  /* Length of the meaningful part of data */
} StringInfo;

typedef struct {
    const char *name;
    guint len;
} SslDigestAlgo;


typedef struct _SslFlow {
    guint32 byte_seq;
    guint16 flags;
} SslFlow;

typedef struct _SslCipherSuite {
    gint number;
    gint kex;
    gint enc;
    gint dig;
    ssl_cipher_mode_t mode;
} SslCipherSuite;

typedef struct _SslDecoder {
    const SslCipherSuite *cipher_suite;
    gint compression;
    guchar _mac_key_or_write_iv[48];
    StringInfo mac_key; /* for block and stream ciphers */
    StringInfo write_iv; /* for AEAD ciphers (at least GCM, CCM) */
    SSL_CIPHER_CTX evp;
    guint64 seq;    /**< Implicit (TLS) or explicit (DTLS) record sequence number. */
    guint16 epoch;
    SslFlow *flow;
    StringInfo app_traffic_secret;  /**< TLS 1.3 application traffic secret (if applicable), wmem file scope. */
} SslDecoder;

typedef struct _My_Session{
    const SslCipherSuite *cipher_suite;
    guint16 version;
} My_Session;

/* This holds state information for a SSL conversation */
typedef struct _SslDecryptSession {
    // guchar _master_secret[SSL_MASTER_SECRET_LENGTH];
    guchar _session_id[256];
    guchar _client_random[32];
    guchar _server_random[32];
    StringInfo session_id;
    StringInfo session_ticket;
    StringInfo server_random;
    StringInfo client_random;
    StringInfo master_secret;
    StringInfo handshake_data;
    /* the data store for this StringInfo must be allocated explicitly with a capture lifetime scope */
    StringInfo pre_master_secret;
    guchar _server_data_for_iv[24];
    StringInfo server_data_for_iv;
    guchar _client_data_for_iv[24];
    StringInfo client_data_for_iv;

    gint state;
    const SslCipherSuite *cipher_suite;
    SslDecoder *server;
    SslDecoder *client;
    SslDecoder *server_new;
    SslDecoder *client_new;
#if defined(HAVE_LIBGNUTLS)
    struct cert_key_id *cert_key_id;   /**< SHA-1 Key ID of public key in certificate. */
#endif
    StringInfo psk;
    StringInfo app_data_segment;
    // SslSession session;
    gboolean   has_early_data;

} SslDecryptSession;

//<-------------------------- 变量枚举 -------------------------->
typedef enum {
    MODE_STREAM,    /* GenericStreamCipher */
    MODE_CBC,       /* GenericBlockCipher */
    MODE_GCM,       /* GenericAEADCipher */
    MODE_CCM,       /* AEAD_AES_{128,256}_CCM with 16 byte auth tag */
    MODE_CCM_8,     /* AEAD_AES_{128,256}_CCM with 8 byte auth tag */
    MODE_POLY1305,  /* AEAD_CHACHA20_POLY1305 with 16 byte auth tag (RFC 7905) */
} ssl_cipher_mode_t;

static const SslDigestAlgo digests[]={
    {"MD5",     16},
    {"SHA1",    20},
    {"SHA256",  32},
    {"SHA384",  48},
    {"SM3",     32},
    {"Not Applicable",  0},
};

//<-------------------------- utils函数定义 -------------------------->


//<-------------------------- 函数定义 -------------------------->



/** Search for the specified cipher suite id
 @param num the id of the cipher suite to be searched
 @return pointer to the cipher suite struct (or NULL if not found). */
extern const SslCipherSuite *ssl_find_cipher(int num);


#endif // __PACKET_TLS_UTILS_H__