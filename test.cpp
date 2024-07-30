#include "my_utils.h"
#include <stdint.h>
#include <stdio.h>



int main() {

    StringInfo label_seed;
    StringInfo *rnd1 = new StringInfo;
    StringInfo *rnd2 = new StringInfo;
    StringInfo *secret = new StringInfo;
    StringInfo *out = new StringInfo;
    const char *usage = "key expansion";

    // number是协商后确定的套件
    // 根据number确定套件...
    const SslCipherSuite *cs = ssl_find_cipher(0xC02F);


    // 需要转换为16进制
    rnd1->data = convertHexStringToUCharArray(
        "0a38e537841158e3d25a69314826eec0175d221754b592dba20d881a577a9efb");
    secret->data = convertHexStringToUCharArray(
        "99b133665bed69448012c527841e64c8ba5c57ba7b70921d3c9d9441a12cdc68");
    rnd2->data = convertHexStringToUCharArray(
        "66a67e9f6c16ffdf3622cdde89e62ef3112c79983d08352e67d859ad30b1d297");
    
    rnd1->data_len = strlen(reinterpret_cast<const char *>(rnd1->data));
    rnd2->data_len = strlen(reinterpret_cast<const char *>(rnd2->data));
    secret->data_len = strlen((char *)secret->data);
    // 先是usage，然后是rnd1，然后是rnd2
    // rnd1是server_random，rnd2是client_random
    //  printf("secret->data_len %d\n", secret->data_len);

    //
    // generate_material

    generate_key_material(cs, secret, usage, rnd1, rnd2, out);

    tls12_prf(8,secret, "extended master secret", rnd2, rnd1, out,48);
    //输出在 同目录下 ssl_dubug_file.txt
    return 0;
}


// sudo apt-get install libgcrypt20-dev
// g++ -o test test.cpp -lgcrypt
// md=8
// git push -u origin main
