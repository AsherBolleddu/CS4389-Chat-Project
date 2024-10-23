#ifndef CRYPTO_H
#define CRYPTO_H

#define AES_KEY_LEN 32
#define AES_IV_SIZE 16
#define BUFFER_SIZE 1024
#define MAX_CLIENTS 10

// Structure to hold key and IV pairs
typedef struct {
    unsigned char key[AES_KEY_LEN];
    unsigned char iv[AES_IV_SIZE];
} AESKeyIV;

// Function to encrypt the message
int aes_encrypt(const unsigned char* plaintext, int plaintext_len, unsigned char* key, unsigned char* iv,
                unsigned char* ciphertext);

// Function to decrypt the message
int aes_decrypt(const unsigned char* ciphertext, int ciphertext_len, unsigned char* key, unsigned char* iv,
                unsigned char* plaintext);

#endif // CRYPTO_H