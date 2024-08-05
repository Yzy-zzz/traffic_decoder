#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>

void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

void encrypt_with_aes_gcm(const unsigned char *key, const unsigned char *plaintext, int plaintext_len,
                          const unsigned char *aad, int aad_len, const unsigned char *nonce, unsigned char *ciphertext,
                          unsigned char *tag) {
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) handleErrors();

    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce)) handleErrors();

    if (aad && aad_len > 0) {
        if (1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) handleErrors();
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) handleErrors();
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
    ciphertext_len += len;

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag)) handleErrors();

    EVP_CIPHER_CTX_free(ctx);
}

void hkdf(const unsigned char *salt, int salt_len, const unsigned char *ikm, int ikm_len,
          const unsigned char *info, int info_len, unsigned char *okm, int okm_len) {
    EVP_PKEY_CTX *pctx;

    if (!(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL))) handleErrors();

    if (1 != EVP_PKEY_derive_init(pctx)) handleErrors();
    if (1 != EVP_PKEY_CTX_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXTRACT_AND_EXPAND)) handleErrors();
    if (1 != EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256())) handleErrors();
    if (1 != EVP_PKEY_CTX_set1_hkdf_salt(pctx, salt, salt_len)) handleErrors();
    if (1 != EVP_PKEY_CTX_set1_hkdf_key(pctx, ikm, ikm_len)) handleErrors();
    if (1 != EVP_PKEY_CTX_add1_hkdf_info(pctx, info, info_len)) handleErrors();
    if (1 != EVP_PKEY_derive(pctx, okm, &okm_len)) handleErrors();

    EVP_PKEY_CTX_free(pctx);
}

int main() {
    const unsigned char aes_key[16] = {0xe8, 0x7b, 0x64, 0x25, 0x70, 0xc4, 0x15, 0x32, 0xee, 0x09, 0xab, 0x69, 0xd0, 0x3e, 0xd5, 0x13};
    const unsigned char nonce[12] = {0xb3, 0x8b, 0x7a, 0xf6, 0x3d, 0x0f, 0x5f, 0xff, 0xcc, 0x1c, 0xb4, 0x09};
    const unsigned char client_hello_random[32] = {0x66, 0xa6, 0x7e, 0x9f, 0x6c, 0x16, 0xff, 0xdf, 0x36, 0x22, 0xcd, 0xde, 0x89, 0xe6, 0x2e, 0xf3, 0x11, 0x2c, 0x79, 0x98, 0x3d, 0x08, 0x35, 0x2e, 0x67, 0xd8, 0x59, 0xad, 0x30, 0xb1, 0xd2, 0x97};
    unsigned char ciphertext[32];
    unsigned char tag[16];

    encrypt_with_aes_gcm(aes_key, client_hello_random, sizeof(client_hello_random), NULL, 0, nonce, ciphertext, tag);

    unsigned char seed[16];
    memcpy(seed, ciphertext, 16);

    unsigned char derived_key[32];
    hkdf(NULL, 0, seed, sizeof(seed), (const unsigned char *)"handshake data", strlen("handshake data"), derived_key, sizeof(derived_key));

    unsigned char private_key[32];
    memcpy(private_key, derived_key, 32);

    printf("Private Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", private_key[i]);
    }
    printf("\n");

    return 0;
}
