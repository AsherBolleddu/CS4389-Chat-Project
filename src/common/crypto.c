#include "crypto.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <openssl/evp.h>

// Function to calculate message hash using modern EVP interface
int calculate_message_hash(const unsigned char* message, size_t message_len, unsigned char* hash, unsigned int* hash_len) {
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        return -1;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestUpdate(mdctx, message, message_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    if (EVP_DigestFinal_ex(mdctx, hash, hash_len) != 1) {
        EVP_MD_CTX_free(mdctx);
        return -1;
    }

    EVP_MD_CTX_free(mdctx);
    return 0;
}

//Function to encrypt the message
int aes_encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv,
                unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int ciphertext_len;

    //Create and initialize context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("Failed to create context");
        return -1;
    }

    //Initialize encryption operation with AES-256
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        perror("Failed to initialize encryption operation");
        return -1;
    }

    //Provide the message to be encrypted
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        perror("Failed to encrypt message");
        return -1;
    }
    ciphertext_len = len;

    //Finalize the encryption
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        return -1;
    }
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

//Function to decrypt the message
int aes_decrypt(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv,
                unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx;
    int len;
    int plaintext_len;

    // Create and initialize the context
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        perror("Failed to create context");
        return -1;
    }

    // Initialize the decryption operation with AES-256-CBC
    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        perror("Failed to initialize decryption");
        return -1;
    }

    // Provide the message to be decrypted, and obtain the plaintext output
    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len)) {
        perror("Failed to decrypt");
        return -1;
    }
    plaintext_len = len;

    // Finalize the decryption
    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        perror("Failed to finalize decryption");
        return -1;
    }
    plaintext_len += len;

    // Clean up
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}