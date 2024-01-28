#include <stdio.h>
#include <stdint.h>
#include "my_utils.h"

static int tls_hash(StringInfo *secret, StringInfo *seed, int md,
         StringInfo *out, uint out_len)
{
    /* RFC 2246 5. HMAC and the pseudorandom function
     * '+' denotes concatenation.
     * P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
     *                        HMAC_hash(secret, A(2) + seed) + ...
     * A(0) = seed
     * A(i) = HMAC_hash(secret, A(i - 1))
     */
    u_char     *ptr;
    uint     left, tocpy;
    u_char    *A;
    uint8_t     _A[DIGEST_MAX_SIZE], tmp[DIGEST_MAX_SIZE];
    uint     A_l, tmp_l;
    SSL_HMAC  hm;

    ptr  = out->data;
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
        tocpy = left<tmp_l ? left : tmp_l;
        memcpy(ptr, tmp, tocpy);
        ptr += tocpy;
        left -= tocpy;
    }
    ssl_hmac_cleanup(&hm);
    out->data_len = out_len;

    // printf("out->data_len %d\n", out->data_len);
    // printf("out->data %s\n", out->data);
    ssl_print_data("hash out", out->data,out_len);
    return 0;
}

//tls12_prf函数实现


int main() {

    StringInfo label_seed;
    int md=8;//SHA256
    StringInfo* rnd1=new StringInfo;
    StringInfo* rnd2=new StringInfo;
    StringInfo* secret=new StringInfo;
    const char* usage = "key expansion";

    //需要转换为16进制
    rnd2->data=convertHexStringToUCharArray("10e8a2c974cca2e23d8db5960a97d41be509d3dd9e6390d2a9c01a71eff8e4f1");
    secret->data=convertHexStringToUCharArray("33e57feee8319c034d9d714708316922d522c5bb43bee30c50ac105e58032d9fcc0f28ace73a91a467186d88e644ecac");
    rnd1->data=convertHexStringToUCharArray("ba719e7fa9af1edaaa1997e6d1c3ac0c7452b212452b382fdbf830c03627b3fb"); 
    rnd1->data_len = strlen(reinterpret_cast<const char*>(rnd1->data));
    rnd2->data_len = strlen(reinterpret_cast<const char*>(rnd2->data));
    secret->data_len = strlen((char*)secret->data);
    //先是usage，然后是rnd1，然后是rnd2
    //rnd1是server_random，rnd2是client_random
    // printf("secret->data_len %d\n", secret->data_len);

    size_t usage_len = strlen(usage);

    ssl_data_alloc(&label_seed, usage_len+rnd1->data_len+rnd2->data_len);
    memcpy(label_seed.data, usage, usage_len);

    memcpy(label_seed.data+usage_len, rnd1->data, rnd1->data_len);
    memcpy(label_seed.data+usage_len+rnd1->data_len, rnd2->data, rnd2->data_len);
    
    printf("tls12_prf: tls_hash(hash_alg %s secret_len %d seed_len %d )\n", gcry_md_algo_name(md), secret->data_len, label_seed.data_len);

    ssl_print_data("tls12_prf: secret", secret->data, secret->data_len);
    ssl_print_data("tls12_prf: seed", label_seed.data, label_seed.data_len);
    
    
    // printf("1");
    StringInfo* out=new StringInfo;
    ssl_data_alloc(out, 104);

    tls_hash(secret, &label_seed, md, out, 104);


    return 0;
}
//g++ -o test test.cpp -lgcrypt
//md=8
