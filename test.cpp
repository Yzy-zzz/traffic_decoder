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

    // 根据number确定套件...
    const SslCipherSuite *cs = ssl_find_cipher(0xC02F);

    // My_Session session;
    
    
    // out_len是hash后面的输出大小

    // 需要转换为16进制

    rnd1->data = convertHexStringToUCharArray(
        "10e8a2c974cca2e23d8db5960a97d41be509d3dd9e6390d2a9c01a71eff8e4f1");
    secret->data = convertHexStringToUCharArray(
        "33e57feee8319c034d9d714708316922d522c5bb43bee30c50ac105e58032d9fcc0f28"
        "ace73a91a467186d88e644ecac");
    rnd2->data = convertHexStringToUCharArray(
        "ba719e7fa9af1edaaa1997e6d1c3ac0c7452b212452b382fdbf830c03627b3fb");
    rnd1->data_len = strlen(reinterpret_cast<const char *>(rnd1->data));
    rnd2->data_len = strlen(reinterpret_cast<const char *>(rnd2->data));
    secret->data_len = strlen((char *)secret->data);
    // 先是usage，然后是rnd1，然后是rnd2
    // rnd1是server_random，rnd2是client_random
    //  printf("secret->data_len %d\n", secret->data_len);

    //
    // generate_material
    generate_key_material(cs, secret, usage, rnd2, rnd1, out);


    
    return 0;
}


// sudo apt-get install libgcrypt20-dev
// g++ -o test test.cpp -lgcrypt
// md=8
// git push -u origin main
