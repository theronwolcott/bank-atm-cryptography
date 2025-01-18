

#define AES_KEY_SIZE 256  // 256-bit key
#define AES_BLOCK_SIZE 16 // AES block size is always 16 bytes

int generate_random_iv(unsigned char *iv, int iv_len);
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
            unsigned char *iv, unsigned char *plaintext);
