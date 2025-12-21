#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sha256.h"
#include <math.h>
#include <time.h>
#include <stdint.h>

const char *STORED_HASH_HEX = "9c3cac217af639559a3d05051c62c8d50469bc7b6800b534e73fcce62b5478a5";
#define TEA_DELTA 0x9e3779b9

void hash_to_string(unsigned char hash[32], char outputBuffer[65]) {
    for(int i = 0; i < 32; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

// --- Алгоритм TEA (Блочное шифрование) ---

// Шифрование одного блока (64 бита / 8 байт)
__declspec(dllexport)
void encrypt_block(uint32_t v[2], uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0, i;
    for (i = 0; i < 32; i++) {
        sum += TEA_DELTA;
        v0 += ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        v1 += ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
    }
    v[0] = v0; v[1] = v1;
}

// Расшифровка одного блока (64 бита / 8 байт)
__declspec(dllexport)
void decrypt_block(uint32_t v[2], uint32_t k[4]) {
    uint32_t v0 = v[0], v1 = v[1], sum = 0xC6EF3720, i; 
    for (i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + k[2]) ^ (v0 + sum) ^ ((v0 >> 5) + k[3]);
        v0 -= ((v1 << 4) + k[0]) ^ (v1 + sum) ^ ((v1 >> 5) + k[1]);
        sum -= TEA_DELTA;
    }
    v[0] = v0; v[1] = v1;
}

// Вспомогательная функция для генерации ключа из строки (128 бит)
__declspec(dllexport)
void prepare_key_from_string(const char* password, uint32_t key[4]) {
    unsigned char hash[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char*)password, strlen(password));
    sha256_final(&ctx, hash);
    
    // Берем первые 16 байт (128 бит) хэша как ключ для TEA
    memcpy(key, hash, 16);
}

// --- Остальные функции ---

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

__declspec(dllexport) void randomPasswordGeneration(int password_length, char* output_password) {
    static int seeded = 0;
    if (!seeded) {
        srand((unsigned int)(time(NULL)));
        seeded = 1;
    }

    char numbers[] = "0123456789";
    char letter[] = "abcdefghijklmnopqrstuvwxyz";
    char LETTER[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    char symbols[] = "!@#$^&*?";

    for (int i = 0; i < password_length; i++) {
        int randomizer = rand() % 4;
        if (randomizer == 1) output_password[i] = numbers[rand() % 10];
        else if (randomizer == 2) output_password[i] = symbols[rand() % 8];
        else if (randomizer == 3) output_password[i] = LETTER[rand() % 26];
        else output_password[i] = letter[rand() % 26];
    }
    output_password[password_length] = '\0';
}