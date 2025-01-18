#include "bank.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include "hash_table.h"
#include <unistd.h>
#include <limits.h>
#include "ssl.h"
#include <openssl/sha.h>

int sequence = 0;

Bank *bank_create(unsigned char *aes_key)
{
    Bank *bank = (Bank *)malloc(sizeof(Bank));
    if (bank == NULL)
    {
        perror("Could not allocate Bank");
        exit(1);
    }

    // Set up the network state
    bank->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&bank->rtr_addr, sizeof(bank->rtr_addr));
    bank->rtr_addr.sin_family = AF_INET;
    bank->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bank->rtr_addr.sin_port = htons(ROUTER_PORT);

    bzero(&bank->bank_addr, sizeof(bank->bank_addr));
    bank->bank_addr.sin_family = AF_INET;
    bank->bank_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    bank->bank_addr.sin_port = htons(BANK_PORT);
    bind(bank->sockfd, (struct sockaddr *)&bank->bank_addr, sizeof(bank->bank_addr));

    // Set up the protocol state
    bank->users = hash_table_create(10);
    memcpy(bank->aes_key, aes_key, AES_KEY_SIZE / 8);

    return bank;
}

void bank_free(Bank *bank)
{
    if (bank != NULL)
    {
        close(bank->sockfd);

        hash_table_free(bank->users);
        free(bank);
    }
}

ssize_t bank_send(Bank *bank, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(bank->sockfd, data, data_len, 0,
                  (struct sockaddr *)&bank->rtr_addr, sizeof(bank->rtr_addr));
}

ssize_t bank_recv(Bank *bank, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(bank->sockfd, data, max_data_len, 0, NULL, NULL);
}

void remove_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
    {
        str[len - 1] = '\0'; // Remove the newline character
    }
}

int *allocate_int(int value)
{
    int *ptr = (int *)malloc(sizeof(int));
    if (ptr == NULL)
    {
        fprintf(stderr, "Memory allocation failed");
        exit(1);
    }
    *ptr = value;
    return ptr;
}

void bank_process_local_command(Bank *bank, char *command, size_t len)
{
    // Parse the command into tokens
    remove_newline(command);
    char *tokens[4] = {0};
    size_t token_count = 0;
    char *token = strtok(command, " ");
    while (token != NULL && token_count < 4)
    {
        tokens[token_count++] = token;
        token = strtok(NULL, " ");
    }

    // Handle different commands
    if (token_count == 0)
    {
        printf("Invalid command 1\n");
        return;
    }

    // CREATE-USER command
    if (strcmp(tokens[0], "create-user") == 0)
    {
        if (token_count != 4 || !is_valid_username(tokens[1]) || !is_valid_pin(tokens[2]) || !is_valid_balance(tokens[3]))
        {
            printf("Usage:  create-user <user-name> <pin> <balance>\n");
            return;
        }

        char *username = tokens[1];
        int pin = atoi(tokens[2]);
        int balance = atoi(tokens[3]);

        // Check if user exists
        if (hash_table_find(bank->users, username) != NULL)
        {
            printf("Error:  user %s already exists\n", username);
            return;
        }

        // Create user and write to .card file
        if (create_user(bank, username, pin, balance) != 0)
        {
            printf("Error creating card file for user %s\n", username);
            return;
        }

        printf("Created user %s\n", username);
    }

    else if (strcmp(tokens[0], "deposit") == 0)
    {
        if (token_count != 3 || !is_valid_username(tokens[1]) || !is_valid_balance(tokens[2]))
        {
            printf("Usage:  deposit <user-name> <amt>\n");
            return;
        }

        char *username = tokens[1];
        int amount = atoi(tokens[2]);

        printf("username: -%s-, amount: %i\n", username, amount);

        // Check if user exists, stop if not
        int *balance_ptr = (int *)hash_table_find(bank->users, username);
        if (balance_ptr == NULL)
        {
            printf("No such user\n");
            return;
        }

        // Check for overflow
        int balance = *balance_ptr;
        if (balance > INT_MAX - amount)
        {
            printf("Too rich for this program\n");
            return;
        }
        *balance_ptr += amount;

        printf("$%d added to %s's account\n", amount, username);
    }
    // BALANCE command
    else if (strcmp(tokens[0], "balance") == 0)
    {
        if (token_count != 2 || !is_valid_username(tokens[1]))
        {
            printf("Usage:  balance <user-name>\n");
            return;
        }

        char *username = tokens[1];

        // Check if user exists, stop if not
        int *balance_ptr = hash_table_find(bank->users, username);
        if (balance_ptr == NULL)
        {
            printf("No such user\n");
            return;
        }

        printf("$%d\n", *balance_ptr);
    }
    // Invalid command
    else
    {
        printf("Invalid command\n");
    }
}

// Helper Functions
int is_valid_username(const char *str)
{

    for (size_t i = 0; str[i] != '\0'; i++)
    {
        if (!isalpha(str[i]))
            return 0;
    }
    if (strlen(str) > 250)
    {
        return 0;
    }
    return 1;
}

int is_valid_pin(const char *pin)
{
    return strlen(pin) == 4 && isdigit(pin[0]) && isdigit(pin[1]) && isdigit(pin[2]) && isdigit(pin[3]);
}

int is_valid_balance(const char *balance)
{
    for (size_t i = 0; balance[i] != '\0'; i++)
    {
        if (!isdigit(balance[i]))
            return 0;
    }
    return atoi(balance) >= 0;
}

int create_user(Bank *bank, const char *username, int pin, int balance)
{

    // Allocate memory for username
    char *username_copy = strdup(username);
    if (username_copy == NULL)
    {
        fprintf(stderr, "Memory allocation failed for username\n");
        return -1;
    }
    // Add balance to the hash table
    int *balance_ptr = allocate_int(balance);
    hash_table_add(bank->users, username_copy, balance_ptr);

    // Hash the input PIN using SHA-256
    char pin_str[16];
    snprintf(pin_str, sizeof(pin_str), "%d", pin);

    size_t combination_size = strlen(pin_str) + (AES_KEY_SIZE / 8);
    unsigned char combination_string[combination_size];

    // Copy pin_str into combination_string
    memcpy(combination_string, pin_str, strlen(pin_str));

    // Append aes_key to combination_string
    memcpy(combination_string + strlen(pin_str), bank->aes_key, AES_KEY_SIZE / 8);

    // Calculate the SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(combination_string, combination_size, hash);

    // Write the hash to a .card file
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.card", username);
    FILE *file = fopen(filename, "w");
    if (!file)
    {
        // Roll back hash table addition
        hash_table_del(bank->users, (char *)username);
        free(balance_ptr);
        free(username_copy);
        return -1;
    }

    // Convert the hash to a hexadecimal string and write it to the file
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        fprintf(file, "%02x", hash[i]);
    }
    fprintf(file, "\n");
    fclose(file);

    return 0; // Success

    // // Write the PIN to a .card file
    // char filename[256];
    // snprintf(filename, sizeof(filename), "%s.card", username);
    // FILE *file = fopen(filename, "w");
    // if (!file)
    // {
    //     // Roll back hash table addition
    //     hash_table_del(bank->users, (char *)username);
    //     free(balance_ptr);
    //     return -1;
    // }

    // fprintf(file, "PIN: %d\n", pin);
    // fclose(file);

    // return 0; // Success
}

void bank_process_remote_command(Bank *bank, char *command, size_t len)
{
    // printf("bank_process_remote_command()\n");
    // TODO: Implement the bank side of the ATM-bank protocol
    // command[len] = 0;

    // Decrypt the ciphertext
    unsigned char decryptedtext[512];
    int decryptedtext_len = decrypt((unsigned char *)(command + AES_BLOCK_SIZE), len - AES_BLOCK_SIZE, bank->aes_key, (unsigned char *)command, decryptedtext);

    // Null-terminate the decrypted text
    decryptedtext[decryptedtext_len] = '\0';

    // Typecast to `char *`
    char *decrypted_str = (char *)decryptedtext;

    // printf("Decrypted command is:\n%s\n", decrypted_str);

    char *tokens[4] = {0};
    size_t token_count = 0;
    char *token = strtok(decrypted_str, " ");
    while (token != NULL && token_count < 4)
    {
        tokens[token_count++] = token;
        token = strtok(NULL, " ");
    }

    char return_val[256];

    if (strcmp(tokens[0], "withdraw") == 0)
    {

        char *username = tokens[2];
        int amount = atoi(tokens[1]);
        int seq = atoi(tokens[3]);

        if (seq <= sequence)
        {
            bank_send(bank, "3", 1);
            return;
        }
        sequence++;

        // printf("withdraw: username: -%s-, amount: %i\n", username, amount);

        // Check if user exists, stop if not
        int *balance_ptr = (int *)hash_table_find(bank->users, username);
        if (balance_ptr == NULL)
        {
            bank_send(bank, "2", 1);
            // printf("No such user\n");
            return;
        }

        // Check for overflow
        int balance = *balance_ptr;
        if (balance > INT_MAX - amount)
        {
            bank_send(bank, "1", 1);
            // printf("Too rich for this program\n");
            return;
        }
        if (amount > balance)
        {
            bank_send(bank, "4", 1);
            // printf("Insufficient funds\n");
            return;
        }
        *balance_ptr -= amount;

        // printf("$%d removed from %s's account\n", amount, username);
        bank_send(bank, "0", 1);
    }
    else if (strcmp(tokens[0], "balance") == 0)
    {

        char *username = tokens[1];
        int seq = atoi(tokens[2]);

        if (seq <= sequence)
        {
            bank_send(bank, "3", 1);
            return;
        }
        sequence++;
        // printf("balance: username: -%s-, seq: %i\n", username, seq);

        // Check if user exists, stop if not
        int *balance_ptr = (int *)hash_table_find(bank->users, username);
        if (balance_ptr == NULL)
        {
            bank_send(bank, "2", 1);
            // printf("No such user\n");
            return;
        }

        // Check for overflow
        int balance = *balance_ptr;

        // printf("$%d removed from %s's account\n", amount, username);
        sprintf(return_val, "$%d", balance);
        bank_send(bank, return_val, strlen(return_val));
    }
    else if (strcmp(tokens[0], "user-exist") == 0)
    {

        char *username = tokens[1];
        int seq = atoi(tokens[2]);

        if (seq <= sequence)
        {
            bank_send(bank, "3", 1);
            return;
        }
        sequence++;
        // printf("balance: username: -%s-, seq: %i\n", username, seq);

        // Check if user exists, stop if not
        int *balance_ptr = (int *)hash_table_find(bank->users, username);
        if (balance_ptr == NULL)
        {
            bank_send(bank, "2", 1);
            // printf("No such user\n");
            return;
        }
        else
        {
            bank_send(bank, "0", 1);
            return;
        }
    }

    /*
     * The following is a toy example that simply receives a
     * string from the ATM, prepends "Bank got: " and echoes
     * it back to the ATM before printing it to stdout.
     */

    // char sendline[1000];
    // command[len]=0;
    // sprintf(sendline, "Bank got: %s", command);
    // bank_send(bank, sendline, strlen(sendline));
    // printf("Received the following:\n");
    // fputs(command, stdout);
}
