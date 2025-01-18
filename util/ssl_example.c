#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <string.h>
#include <stdio.h>
#include "ssl.h"

int main(void)
{
    // Load the human-readable error strings for libcrypto (optional)
    ERR_load_crypto_strings();

    // Sample 256-bit AES key
    unsigned char key[32];
    if (!RAND_bytes(key, sizeof(key)))
    {
        fprintf(stderr, "Failed to generate random AES key\n");
        return 1;
    }

    // Generate random IV
    unsigned char iv[AES_BLOCK_SIZE];
    if (!generate_random_iv(iv, AES_BLOCK_SIZE))
    {
        return 1;
    }

    // Plaintext to encrypt
    unsigned char *plaintext = (unsigned char *)"This is a test plaintext message.";

    unsigned char ciphertext[128];
    unsigned char decryptedtext[256];

    // Encrypt the plaintext
    int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);
    printf("ciphertext_len: %i\n", ciphertext_len);

    char combo[256];

    memcpy(combo, iv, AES_BLOCK_SIZE);
    memcpy(combo + AES_BLOCK_SIZE, ciphertext, ciphertext_len);
    combo[AES_BLOCK_SIZE + ciphertext_len] = '\0';

    printf("combo: %s\n", combo);

    // Decrypt the ciphertext
    int decryptedtext_len = decrypt((unsigned char *)(combo + AES_BLOCK_SIZE), ciphertext_len, key, (unsigned char *)combo, decryptedtext);

    // Null-terminate the decrypted text
    decryptedtext[decryptedtext_len] = '\0';

    // Show the results
    printf("Ciphertext is:\n");
    for (int i = 0; i < ciphertext_len; i++)
    {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Typecast to `char *`
    char *decrypted_str = (char *)decryptedtext;

    printf("Decrypted text is:\n%s\n", decrypted_str);

    // Clean up
    EVP_cleanup();
    ERR_free_strings();

    return 0;
}
