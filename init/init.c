#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

// Function to generate a random AES key (256-bit)
int generate_aes_key(unsigned char *key, int key_size)
{
    // Generate a random key of the specified size (in bits)
    if (RAND_bytes(key, key_size / 8) != 1)
    {
        return -1; // Error generating key
    }
    return 0; // Success
}

// Function to write key to a file
int write_key_to_file(const char *filename, unsigned char *key, int key_size)
{
    FILE *file = fopen(filename, "wb");
    if (!file)
    {
        return -1; // Error opening file
    }

    // Write the AES key to the file
    size_t written = fwrite(key, 1, key_size / 8, file);
    fclose(file);

    return (written == key_size / 8) ? 0 : -1; // Ensure full key is written
}

int file_exists(const char *filename)
{
    if (access(filename, F_OK) == 0)
    {
        return 1;
    }
}

// Main function for the 'init' program
int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <path2>/<init-fname>\n", argv[0]);
        return 62; // Error code for incorrect usage
    }

    // Parse the path and filename
    char *path = argv[1];
    char *init_fname = strrchr(path, '/');
    if (init_fname)
    {
        init_fname++; // Move past the '/'
    }
    else
    {
        init_fname = path; // No directory, use the full path as filename
    }

    // Generate AES key (256-bit)
    unsigned char aes_key[32]; // 256-bit key
    if (generate_aes_key(aes_key, 256) != 0)
    {
        fprintf(stderr, "Error creating initialization files\n");
        // fprintf(stderr, "Error generating AES key\n");
        return 64;
    }

    // Prepare the full file paths
    char bank_filename[512];
    char atm_filename[512];

    snprintf(bank_filename, sizeof(bank_filename), "%s.bank", path);
    snprintf(atm_filename, sizeof(atm_filename), "%s.atm", path);

    // Check if filenames already exist
    if (file_exists(atm_filename) == 1 || file_exists(bank_filename) == 1)
    {
        fprintf(stderr, "Error: one of the files already exists\n");
        return 63;
    }

    // Write the AES key to both .bank and .atm files
    if (write_key_to_file(bank_filename, aes_key, 256) != 0)
    {
        fprintf(stderr, "Error creating initialization files\n");
        // fprintf(stderr, "Error writing to %s\n", bank_filename);
        return 64;
    }

    if (write_key_to_file(atm_filename, aes_key, 256) != 0)
    {
        fprintf(stderr, "Error creating initialization files\n");
        // fprintf(stderr, "Error writing to %s\n", atm_filename);
        return 64;
    }

    // printf("AES key successfully written to %s and %s\n", bank_filename, atm_filename);
    printf("Successfully initialized bank state\n");
    return 0;
}
