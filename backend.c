#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"

const char *STORED_HASH_HEX = "9c3cac217af639559a3d05051c62c8d50469bc7b6800b534e73fcce62b5478a5";
const char XOR_KEY = 51;

void hash_to_string(unsigned char hash[32], char outputBuffer[65]) {
    for(int i = 0; i < 32; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

int check_master_key(const char *input_key) {
    unsigned char hash[32];
    char hashString[65];
    SHA256_CTX ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char*)input_key, strlen(input_key));
    sha256_final(&ctx, hash);

    hash_to_string(hash, hashString);

    if (strcmp(hashString, STORED_HASH_HEX) == 0) {
        return 1; 
    }
    return 0;
}


void xor_encrypt_decrypt(char *text) {
    for(int i = 0; text[i] != '\0'; i++) {
        text[i] = text[i] ^ XOR_KEY;
    }
}
