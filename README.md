# ATM and Bank Protocol Implementation

This project implements a secure communication protocol between an ATM and a bank server, ensuring the integrity and confidentiality of transactions. It uses AES encryption, sequence numbers, and a shared symmetric key for secure message exchanges.

## Overview

The system consists of three programs:
1. **`init`**: Initializes the system by generating key files for the bank and ATM.
2. **`bank`**: Manages user accounts and processes commands such as creating users, depositing money, and checking balances.
3. **`atm`**: Allows users to interact with the bank securely, supporting operations such as beginning a session, withdrawing money, and checking balances.

## Features

- **Secure Communication**: Messages between the ATM and the bank are encrypted using AES with a shared symmetric key.
- **Replay Protection**: Each message includes a unique sequence number to prevent replay attacks.
- **Integrity Assurance**: Encrypted messages ensure that transaction details (e.g., withdrawal amounts, account names) cannot be modified by attackers.
- **Confidential PIN Verification**: User PINs are encrypted during transmission and verified securely by the bank.
- **Unlimited Transactions Per Session**: Users can perform multiple operations during a single session.

## Security Measures

### Encryption
- Messages are encrypted using AES encryption with a unique key generated during initialization.
- A one-time IV is prepended to each encrypted message to ensure message uniqueness, even for identical transactions.

### Sequence Numbers
- Every transaction includes a unique sequence number that increments with each message. 
- Sequence numbers prevent replay attacks by ensuring that old or duplicate transactions are rejected.

### Card Files
- Each user has a `.card` file containing their encrypted PIN and key information. These files are generated during user creation and are essential for authentication.

## Vulnerabilities Addressed

1. **Modification of Withdrawal Amounts**: AES encryption prevents attackers from altering withdrawal amounts in transit.
2. **Modification of Accounts**: Encrypting the entire message ensures attackers cannot change the account associated with a transaction.
3. **Replay Attacks**: Sequence numbers prevent duplicate transactions from being processed.
4. **Impersonation of Users**: PINs are encrypted during transmission, making them secure against interception and misuse.
5. **Unauthorized Transactions**: Encryption of the transaction type prevents attackers from converting balance inquiries into withdrawals.

## Usage

### 1. Initialization
Run the `init` program to create the required key and configuration files for the bank and ATM:

```bash
% ./init <init-filename>
```

### 2. Bank Program
Start the bank program with the initialization file:

```bash
% ./bank <init-filename>.bank
```

The bank program supports the following commands:
- **`create-user <user-name> <pin> <balance>`**: Creates a new user.
- **`deposit <user-name> <amount>`**: Adds funds to a user's account.
- **`balance <user-name>`**: Displays the user's current balance.

### 3. ATM Program
Start the ATM program with the initialization file:

```bash
% ./atm <init-filename>.atm
```

The ATM supports the following commands:
- **`begin-session <user-name>`**: Starts a session for the specified user after verifying their PIN.
- **`withdraw <amount>`**: Dispenses funds from the user's account if sufficient funds are available.
- **`balance`**: Displays the current balance of the logged-in user.
- **`end-session`**: Ends the current session and logs the user out.

## Example Usage

### Bank Program
```plaintext
BANK: create-user Alice 1234 100
Created user Alice

BANK: balance Alice
$100

BANK: deposit Alice 50
$50 added to Alice's account

BANK: balance Alice
$150
```

### ATM Program
```plaintext
ATM: begin-session Alice
PIN? 1234
Authorized

ATM (Alice): balance
$150

ATM (Alice): withdraw 20
$20 dispensed

ATM (Alice): balance
$130

ATM (Alice): end-session
User logged out

ATM: balance
No user logged in
```

## Notes

- **Encryption Requirements**: Ensure OpenSSL is installed to use AES encryption for message security.
- **Error Handling**: The system is designed to handle various error cases, such as invalid commands, insufficient funds, or unauthorized access.
- **Resilience**: The system rolls back any changes in case of errors during critical operations, such as user creation or file access.

## Future Improvements

- **Encrypted Bank Responses**: Currently, responses from the bank are not encrypted, as they do not contain sensitive information. Encrypting responses could add an additional layer of security.
- **Enhanced Authentication**: Adding multi-factor authentication for users could improve security further.

## Conclusion

This project demonstrates a robust implementation of secure communication between an ATM and a bank, leveraging encryption and other mechanisms to address common vulnerabilities and ensure the integrity and confidentiality of financial transactions.
