/*
 * The main program for the Bank.
 *
 * You are free to change this as necessary.
 */

#include <string.h>
#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include "bank.h"
#include "ports.h"

static const char prompt[] = "BANK: ";

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        printf("Usage: %s <path2>/<init-fname>.bank\n", argv[0]);
        return 64; // Return value for incorrect arguments
    }

    const char *bank_file = argv[1];
    unsigned char aes_key[AES_KEY_SIZE / 8]; // Buffer to store the AES key

    // Read AES key from .bank file
    if (read_aes_key(bank_file, aes_key) != 0)
    {
        return 64; // Exit if error reading the key
    }

    // At this point, you have the AES key in aes_key and can proceed with the rest of your bank program

    // Example: Print the key
    // printf("AES Key read from .bank file:\n");
    // for (int i = 0; i < AES_KEY_SIZE / 8; i++) {
    //     printf("%02x", aes_key[i]);
    // }
    // printf("\n");

    int n;
    char sendline[1000];
    char recvline[1000];

    Bank *bank = bank_create(aes_key);

    printf("%s", prompt);
    fflush(stdout);

    while (1)
    {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(0, &fds);
        FD_SET(bank->sockfd, &fds);
        select(bank->sockfd + 1, &fds, NULL, NULL, NULL);

        if (FD_ISSET(0, &fds))
        {
            fgets(sendline, 10000, stdin);
            bank_process_local_command(bank, sendline, strlen(sendline));
            printf("%s", prompt);
            fflush(stdout);
        }
        else if (FD_ISSET(bank->sockfd, &fds))
        {
            n = bank_recv(bank, recvline, 10000);
            bank_process_remote_command(bank, recvline, n);
        }
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