#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include "sha256.h"

// hash from password
const char *STORED_HASH_HEX = "9c3cac217af639559a3d05051c62c8d50469bc7b6800b534e73fcce62b5478a5";

// paths
const char *PASSWORD_FILE = "passwords.txt";
const char *TEMP_FILE = "temp.txt";

//For XOR-encryption
const char XOR_KEY = 51;

// Prototype of encrypt
void encrypt(char* text);

// Converts a 32-byte hash into a 64-character HEX string
void hash_to_string(unsigned char hash[32], char outputBuffer[65]) {
    for(int i = 0; i < 32; i++) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[64] = 0;
}

// XOR Encryption/Decryption (works both ways)
void encrypt(char* text){
    for(int i=0; text[i]!='\0'; i++){
        text[i] = text[i] ^ XOR_KEY;
    }
}

// --- MASTER KEY VERIFICATION (USES SHA-256) ---

int checkMasterKey() {
    char c;
    int i = 0;
    char inputKey[100];
    unsigned char hash[32];
    char hashString[65];
    SHA256_CTX ctx;

    printf("Enter Master Key: ");

    while(1) {
        c = getch();
        if (c == '\r' || c == '\n') {
            break;
        }
        if (c == '\b' && i > 0) {
            i--;
            printf("\b \b");
        }
        else if (i < sizeof(inputKey) - 1 && c >= 32) {
            inputKey[i] = c;
            i++;
            printf("*");
        }
    }
    inputKey[i] = '\0';
    printf("\n");
    if (i == 0) {
        printf("Access Denied (Empty Key).\n");
        return 0;
    }
    // hash from password
    sha256_init(&ctx);
    sha256_update(&ctx, (unsigned char*)inputKey, strlen(inputKey));
    sha256_final(&ctx, hash);

    hash_to_string(hash, hashString);

    // Compare hashes
    if (strcmp(hashString, STORED_HASH_HEX) == 0) {
        printf("Access Granted!\n");
        return 1;
    } else {
        printf("Access Denied.\n");
        return 0;
    }
}

// --functions--

int addPassword(){
    char site[100];
    char login[100];
    char password[100];

    // Opening files
    FILE *file = fopen(PASSWORD_FILE, "a");
    if(file == NULL){
        perror("Error opening file");
        return 1;
    }

    printf("Please, write name of website: \n");
    scanf("%99s", site);
    encrypt(site); // Encryption

    printf("Please, write login: \n");
    scanf("%99s", login);
    encrypt(login);

    printf("Please, write password: \n");
    scanf("%99s", password);
    encrypt(password);

    // Writing to file
    fprintf(file, "site: %s || login: %s || password: %s\n", site, login, password);

    printf("\nData has been saved!\n");
    fclose(file);
    return 0;
}

int showPassword() {
    FILE *file = fopen(PASSWORD_FILE, "r");
    if (file == NULL) {
        printf("File empty or not found.\n");
        return 1;
    }

    char line[512];

    printf("\n--- All Saved Passwords ---\n");
    while (fgets(line, sizeof(line), file)) {
        // --- DECRYPT site ---
        char *siteStart = strstr(line, "site: ");
        if (siteStart != NULL) {
            siteStart += 6;
            char *siteEnd = strstr(siteStart, " ||");
            if (siteEnd != NULL) {
                char backup = *siteEnd;
                *siteEnd = '\0';

                encrypt(siteStart);
                printf("site: %s || ", siteStart);

                *siteEnd = backup;
            }
        }

        // --- DECRYPT login ---
        char *loginStart = strstr(line, "login: ");
        if (loginStart != NULL) {
            loginStart += 7;
            char *loginEnd = strstr(loginStart, " ||");
            if (loginEnd != NULL) {
                char backup = *loginEnd;
                *loginEnd = '\0';

                encrypt(loginStart);
                printf("login: %s || ", loginStart);

                *loginEnd = backup;
            }
        }

        // --- DECRYPT password ---
        char *passStart = strstr(line, "password: ");
        if (passStart != NULL) {
            passStart += 10;
            passStart[strcspn(passStart, "\n")] = '\0';

            encrypt(passStart);
            printf("password: %s", passStart);
        }

        printf("\n");
    }

    fclose(file);
    printf("\nPress Enter to continue...");
    getchar();
    return 0;
}

int deletePassword(){
    char decision[100];
    char line[512];

    FILE *file = fopen(PASSWORD_FILE, "r");
    if(file == NULL){
        printf("No passwords to delete.\n");
        return 1;
    }

    FILE *filepointer = fopen(TEMP_FILE, "w");
    if(filepointer == NULL){
        perror("Error creating temp file");
        fclose(file);
        return 1;
    }

    printf("Please, write a website that you want to delete: ");
    scanf("%99s", decision);
    encrypt(decision);

    char pattern[150];
    sprintf(pattern, "site: %s", decision);

    int found = 0;
    while(fgets(line, sizeof(line), file) != NULL){
        if(strstr(line, pattern) != NULL){
            found = 1;
            continue;
        }
        fputs(line, filepointer);
    }

    fclose(file);
    fclose(filepointer);

    remove(PASSWORD_FILE);
    rename(TEMP_FILE, PASSWORD_FILE);

    if (found) printf("Data was deleted.\n");
    else printf("Website not found.\n");

    return 0;
}

int deleteAllPassword(){
    char answer[10];
    printf("Are you sure that you want to delete all passwords?\n");
    printf("Yes/No: ");
    scanf("%9s", answer);

    if(strcmp(answer, "Yes") == 0 || strcmp(answer, "YES") == 0 || strcmp(answer, "yes") == 0){
        FILE *file = fopen(PASSWORD_FILE, "w"); // Открытие в режиме "w" стирает содержимое
        if(file != NULL){
            fclose(file);
            printf("File is cleared!\n");
        }
    } else {
        printf("Operation cancelled.\n");
    }
    return 0;
}

int main()
{
    // checking key
    if (checkMasterKey() == 0) {
        return 0;
    }

    int choice;
    while(1){
        printf("\nHello! Choose function (1-5): \n");
        printf("1. Add password\n");
        printf("2. Show all passwords\n");
        printf("3. Delete password\n");
        printf("4. Delete all passwords\n");
        printf("5. Exit\n");
        printf("Choice: ");

        // Security from wrong password
        if(scanf("%d", &choice) != 1) {
            while(getchar() != '\n');
            continue;
        }

        if(choice == 1){
            addPassword();
        }
        else if(choice == 2){
            showPassword();
        }
        else if(choice == 3){
            deletePassword();
        }
        else if(choice == 4){
            deleteAllPassword();
        }
        else if(choice == 5){
            printf("Goodbye!\n");
            break;
        }
        else{
            printf("Invalid choice. Try again!\n");
        }
    }
    return 0;
}
