#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include <math.h>
#include <time.h>

const char *STORED_HASH_HEX = "9c3cac217af639559a3d05051c62c8d50469bc7b6800b534e73fcce62b5478a5";
const char XOR_KEY = 51;

void hash_to_string(unsigned char hash[32], char outputBuffer[65]) {
    for(int i = 0; i < 32; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

__declspec(dllexport)
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

__declspec(dllexport)
void xor_encrypt_decrypt(char *text) {
    for(int i = 0; text[i] != '\0'; i++) {
        text[i] = text[i] ^ XOR_KEY;
    }
}

__declspec(dllexport) void randomPasswordGeneration(int password_length, char* output_password) {
    int i = 0;
    int randomizer = 0;

    // For working only 1 time
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)(time(NULL)));
        seeded = 1;
    }

    // Arrays
    char numbers[] = "0123456789";
    char letter[] = "abcdefghijklmnopqrstuvwxyz";
    char LETTER[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char symbols[] = "!@#$^&*?";

    for (i = 0; i < password_length; i++) {
        randomizer = rand() % 4;

        if (randomizer == 1) {
            output_password[i] = numbers[rand() % 10];
        }
        else if (randomizer == 2) {
            output_password[i] = symbols[rand() % 8];
        }
        else if (randomizer == 3) {
            output_password[i] = LETTER[rand() % 26];
        }
        else {
            output_password[i] = letter[rand() % 26];
        }
    }
    output_password[password_length] = '\0';
}
