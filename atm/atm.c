#include "atm.h"
#include "ports.h"
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include "ssl.h"
#include <openssl/sha.h>

int sequence = 1;
int is_logged_in = 0;
char curr_user[256];

ATM *atm_create(unsigned char *aes_key)
{
    ATM *atm = (ATM *)malloc(sizeof(ATM));
    if (atm == NULL)
    {
        perror("Could not allocate ATM");
        exit(1);
    }

    // Set up the network state
    atm->sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&atm->rtr_addr, sizeof(atm->rtr_addr));
    atm->rtr_addr.sin_family = AF_INET;
    atm->rtr_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->rtr_addr.sin_port = htons(ROUTER_PORT);

    bzero(&atm->atm_addr, sizeof(atm->atm_addr));
    atm->atm_addr.sin_family = AF_INET;
    atm->atm_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    atm->atm_addr.sin_port = htons(ATM_PORT);
    bind(atm->sockfd, (struct sockaddr *)&atm->atm_addr, sizeof(atm->atm_addr));

    // Set up the protocol state
    memcpy(atm->aes_key, aes_key, AES_KEY_SIZE / 8);

    return atm;
}

void atm_free(ATM *atm)
{
    if (atm != NULL)
    {
        close(atm->sockfd);
        free(atm);
    }
}

ssize_t atm_send(ATM *atm, char *data, size_t data_len)
{
    // Returns the number of bytes sent; negative on error
    return sendto(atm->sockfd, data, data_len, 0,
                  (struct sockaddr *)&atm->rtr_addr, sizeof(atm->rtr_addr));
}

ssize_t atm_recv(ATM *atm, char *data, size_t max_data_len)
{
    // Returns the number of bytes received; negative on error
    return recvfrom(atm->sockfd, data, max_data_len, 0, NULL, NULL);
}

void remove_newline(char *str)
{
    size_t len = strlen(str);
    if (len > 0 && str[len - 1] == '\n')
    {
        str[len - 1] = '\0'; // Remove the newline character
    }
}
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
int verify_user_pin(ATM *atm, const char *username, int input_pin)
{
    // Construct the filename for the .card file
    char filename[256];
    snprintf(filename, sizeof(filename), "%s.card", username);

    // Open the file for reading
    FILE *file = fopen(filename, "r");
    if (!file)
    {
        // Handle file not found or read error
        fprintf(stderr, "Error: Could not open file %s\n", filename);
        return -1; // Indicate failure (e.g., file doesn't exist)
    }

    // Read the hash from the file
    char hash_from_file[SHA256_DIGEST_LENGTH * 2 + 1]; // Each byte is represented by two hex digits, plus null terminator
    if (fscanf(file, "%64s", hash_from_file) != 1)
    {
        // Handle read error or unexpected format
        fprintf(stderr, "Error: Could not read hash from file %s\n", filename);
        fclose(file);
        return -1; // Indicate failure
    }

    // Close the file after reading
    fclose(file);

    // Hash the input PIN using SHA-256
    char pin_str[16];
    snprintf(pin_str, sizeof(pin_str), "%d", input_pin);

    size_t combination_size = strlen(pin_str) + (AES_KEY_SIZE / 8);
    unsigned char combination_string[combination_size];

    // Copy pin_str into combination_string
    memcpy(combination_string, pin_str, strlen(pin_str));

    // Append aes_key to combination_string
    memcpy(combination_string + strlen(pin_str), atm->aes_key, AES_KEY_SIZE / 8);

    // Calculate the SHA-256 hash
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(combination_string, combination_size, hash);

    // Convert the hash to a hexadecimal string for comparison
    char hash_str[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        snprintf(&hash_str[i * 2], 3, "%02x", hash[i]);
    }

    // Compare the computed hash with the one from the file
    if (strcmp(hash_from_file, hash_str) == 0)
    {
        return 0; // Success: PIN is correct
    }
    else
    {
        return 1; // Failure: PIN is incorrect
    }
}

void atm_process_command(ATM *atm, char *command)
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

    if (strcmp(tokens[0], "begin-session") == 0)
    {
        if (token_count != 2 || !is_valid_username(tokens[1]))
        {
            printf("Usage: begin-session <user-name>\n");
            return;
        }
        if (is_logged_in > 0)
        {
            printf("A user is already logged in\n");
            return;
        }

        // USER EXISTS?
        // call to bank to check if user actually exists
        unsigned char plaintext[512] = {0}; // Initialize the string buffer
        sprintf(plaintext, "user-exist %s %d", tokens[1], sequence++);
        unsigned char ciphertext[512]; // This will hold the encrypted data

        int data_len = strlen((char *)plaintext);

        // Generate random IV
        unsigned char iv[AES_BLOCK_SIZE];
        if (!generate_random_iv(iv, AES_BLOCK_SIZE))
        {
            return 1;
        }

        // Encrypt the plaintext
        int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), atm->aes_key, iv, ciphertext);
        // printf("ciphertext_len: %i\n", ciphertext_len);
        // printf("ciphertext: %s\n", ciphertext);

        char combo[512 + AES_BLOCK_SIZE] = {0}; // the combined iv + ciphertext to send over the wire

        memcpy(combo, iv, AES_BLOCK_SIZE);
        memcpy(combo + AES_BLOCK_SIZE, ciphertext, ciphertext_len);
        combo[AES_BLOCK_SIZE + ciphertext_len] = '\0';
        // printf("combo: %s\n", combo);

        // Talk to server
        char recvline[10000];
        int n;

        atm_send(atm, combo, AES_BLOCK_SIZE + ciphertext_len);
        n = atm_recv(atm, recvline, 10000);
        recvline[n] = 0;

        // Process the response
        if (strcmp(recvline, "0") == 0)
        {
            // Success -- continue
            ;
        }
        else if (strcmp(recvline, "2") == 0)
        {
            // Failure
            printf("No such user\n");
            return;
        }
        else if (strcmp(recvline, "3") == 0)
        {
            // Failure
            printf("Invalid sequence\n");
            return;
        }
        else
        {
            // Unknown response
            printf("Unexpected response from server: %s\n", recvline);
            return;
        }

        while (1 == 1)
        {
            // Ask user for pin
            printf("PIN? ");
            char entered_pin[10];
            if (!fgets(entered_pin, sizeof(entered_pin), stdin))
            {
                printf("Not authorized\n");
                return;
            }
            remove_newline(entered_pin);

            // check .card file to see if hash matches
            int verify_pin = verify_user_pin(atm, tokens[1], atoi(entered_pin));

            if (verify_pin == 0)
            {
                printf("Authorized\n");
                break;
            }
            else if (verify_pin == 1)
            {
                printf("Not authorized\n");
                return;
            }
            else if (verify_pin == -1)
            {
                printf("Unable to access %s's card\n", tokens[1]);
                return;
            }
        }
        // User is in
        strncpy(curr_user, tokens[1], sizeof(curr_user) - 1);
        curr_user[sizeof(curr_user) - 1] = '\0';
        is_logged_in = 1;
        return;
    }
    else if (strcmp(tokens[0], "withdraw") == 0)
    {
        if (!is_logged_in)
        {
            printf("No user logged in\n");
            return;
        }
        if (token_count != 2 || !is_valid_balance(tokens[1]))
        {
            printf("Usage: withdraw <amt>\n");
            return;
        }
        unsigned char plaintext[512] = {0}; // Initialize the string buffer
        sprintf(plaintext, "withdraw %s %s %d", tokens[1], curr_user, sequence++);
        // sprintf(plaintext, "testing");
        unsigned char ciphertext[512]; // This will hold the encrypted data

        int data_len = strlen((char *)plaintext);
        // printf("plaintext: %s\n", plaintext);
        // printf("data_len: %i\n", data_len);

        // Generate random IV
        unsigned char iv[AES_BLOCK_SIZE];
        if (!generate_random_iv(iv, AES_BLOCK_SIZE))
        {
            return 1;
        }

        // Encrypt the plaintext
        int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), atm->aes_key, iv, ciphertext);
        // printf("ciphertext_len: %i\n", ciphertext_len);

        char combo[512 + AES_BLOCK_SIZE] = {0}; // the combined iv + ciphertext to send over the wire

        memcpy(combo, iv, AES_BLOCK_SIZE);
        memcpy(combo + AES_BLOCK_SIZE, ciphertext, ciphertext_len);
        combo[AES_BLOCK_SIZE + ciphertext_len] = '\0';

        // printf("combo: %s\n", combo);

        // Talk to server
        char recvline[10000];
        int n;

        atm_send(atm, combo, AES_BLOCK_SIZE + ciphertext_len);
        // return;
        //  atm_send(atm, result, strlen(result));
        n = atm_recv(atm, recvline, 10000);
        recvline[n] = 0;

        // Process the response
        if (strcmp(recvline, "0") == 0)
        {
            // Success
            printf("$%s dispensed\n", tokens[1]);
        }
        else if (strcmp(recvline, "1") == 0)
        {
            // Failure
            printf("Insufficient funds\n");
        }
        else if (strcmp(recvline, "2") == 0)
        {
            // Failure
            printf("No such user\n");
        }
        else if (strcmp(recvline, "3") == 0)
        {
            // Failure
            printf("Invalid sequence\n");
        }
        else if (strcmp(recvline, "4") == 0)
        {
            // Failure
            printf("Insufficient funds\n");
        }
        else
        {
            // Unknown response
            printf("Unexpected response from server: %s\n", recvline);
        }
    }
    else if (strcmp(tokens[0], "balance") == 0)
    {
        if (!is_logged_in)
        {
            printf("No user logged in\n");
            return;
        }
        if (token_count != 1)
        {
            printf("Usage: balance\n");
            return;
        }
        unsigned char plaintext[512] = {0}; // Initialize the string buffer
        sprintf(plaintext, "balance %s %d", curr_user, sequence++);
        // sprintf(plaintext, "testing");
        unsigned char ciphertext[512]; // This will hold the encrypted data

        int data_len = strlen((char *)plaintext);
        // printf("plaintext: %s\n", plaintext);
        // printf("data_len: %i\n", data_len);

        // Generate random IV
        unsigned char iv[AES_BLOCK_SIZE];
        if (!generate_random_iv(iv, AES_BLOCK_SIZE))
        {
            return 1;
        }

        // Encrypt the plaintext
        int ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), atm->aes_key, iv, ciphertext);
        // printf("ciphertext_len: %i\n", ciphertext_len);

        char combo[512 + AES_BLOCK_SIZE] = {0}; // the combined iv + ciphertext to send over the wire

        memcpy(combo, iv, AES_BLOCK_SIZE);
        memcpy(combo + AES_BLOCK_SIZE, ciphertext, ciphertext_len);
        combo[AES_BLOCK_SIZE + ciphertext_len] = '\0';

        // printf("combo: %s\n", combo);

        // // Decrypt the ciphertext
        // unsigned char decryptedtext[256];
        // int decryptedtext_len = decrypt((unsigned char *)(combo + AES_BLOCK_SIZE), strlen(combo) - AES_BLOCK_SIZE, atm->aes_key, (unsigned char *)combo, decryptedtext);

        // // Null-terminate the decrypted text
        // decryptedtext[decryptedtext_len] = '\0';

        // // Show the results
        // printf("Ciphertext is:\n");
        // for (int i = 0; i < ciphertext_len; i++)
        // {
        //     printf("%02x", ciphertext[i]);
        // }
        // printf("\n");

        // // Typecast to `char *`
        // char *decrypted_str = (char *)decryptedtext;

        // printf("Decrypted text is:\n%s\n", decrypted_str);

        // Talk to server
        char recvline[10000];
        int n;

        atm_send(atm, combo, AES_BLOCK_SIZE + ciphertext_len);
        n = atm_recv(atm, recvline, 10000);
        recvline[n] = 0;

        // Process the response
        if (recvline[0] == '$')
        {
            // Success
            printf("%s\n", recvline);
        }
        else if (strcmp(recvline, "2") == 0)
        {
            // Failure
            printf("No such user\n");
        }
        else if (strcmp(recvline, "3") == 0)
        {
            // Failure
            printf("Invalid sequence\n");
        }
        else
        {
            // Unknown response
            printf("Unexpected response from server: %s\n", recvline);
        }
    }
    else if (strcmp(tokens[0], "end-session") == 0)
    {
        if (!is_logged_in)
        {
            printf("No user logged in\n");
            return;
        }
        is_logged_in = 0;
        curr_user[0] = 0;
        printf("User logged out\n");
    }
    else
    {
        printf("Invalid command\n");
    }
    /*
     * The following is a toy example that simply sends the
     * user's command to the bank, receives a message from the
     * bank, and then prints it to stdout.
     */

    // char recvline[10000];
    // int n;

    // atm_send(atm, command, strlen(command));
    // n = atm_recv(atm,recvline,10000);
    // recvline[n]=0;
    // fputs(recvline,stdout);
}
const char *atm_get_prompt()
{
    static char dynamic_prompt[300];
    if (is_logged_in)
    {
        snprintf(dynamic_prompt, sizeof(dynamic_prompt), "ATM (%s): ", curr_user);
    }
    else
    {
        snprintf(dynamic_prompt, sizeof(dynamic_prompt), "ATM: ");
    }
    return dynamic_prompt;
}
