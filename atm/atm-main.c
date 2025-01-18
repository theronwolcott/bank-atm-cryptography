/*
 * The main program for the ATM.
 *
 * You are free to change this as necessary.
 */

#include "atm.h"
#include <stdio.h>
#include <stdlib.h>

static const char prompt[] = "ATM: ";

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <path2>/<init-fname>.atm\n", argv[0]);
        return 64; // Return value for incorrect arguments
    }

    const char *atm_file = argv[1];
    unsigned char aes_key[AES_KEY_SIZE / 8]; // Buffer to store the AES key

    // Read AES key from .atm file
    if (read_aes_key(atm_file, aes_key) != 0)
    {
        return 64; // Exit if error reading the key
    }

    // At this point, you have the AES key in aes_key and can proceed with the rest of your bank program

    // Example: Print the key
    // printf("AES Key read from .bank file:\n");
    // for (int i = 0; i < AES_KEY_SIZE / 8; i++)
    // {
    //     printf("%02x", aes_key[i]);
    // }
    // printf("\n");

    char user_input[1000];

    ATM *atm = atm_create(aes_key);

    printf("%s", prompt);
    fflush(stdout);

    while (fgets(user_input, 10000, stdin) != NULL)
    {
        atm_process_command(atm, user_input);
        printf("%s", atm_get_prompt());
        fflush(stdout);
    }
    return EXIT_SUCCESS;
}

int read_aes_key(const char *filename, unsigned char *aes_key)
{
    // Open the file for reading
    FILE *file = fopen(filename, "rb"); // "rb" to open in binary mode
    if (!file)
    {
        perror("Unable to open file");
        return -1; // Return an error code if the file cannot be opened
    }

    // Read the AES key from the file
    size_t key_size = AES_KEY_SIZE / 8; // Convert from bits to bytes
    size_t bytes_read = fread(aes_key, 1, key_size, file);
    if (bytes_read != key_size)
    {
        fprintf(stderr, "Error reading AES key\n");
        fclose(file);
        return -1; // Return an error if the number of bytes read is incorrect
    }

    fclose(file); // Close the file after reading
    return 0;     // Return success
}
