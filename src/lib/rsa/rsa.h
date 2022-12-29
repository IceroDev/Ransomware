#ifndef RANSOMWARE_RSA_H
#define RANSOMWARE_RSA_H

#include "rsa.h"

#include <stdbool.h>
#include <openssl/rsa.h>

#define RSA_ENCRYPTION_SIZE 256

typedef enum RSATask {
    RSA_ENCRYPT,
    RSA_DECRYPT
} RSATask;

RSA *newRSA(char *key, bool is_public);

int rsaTask(RSA *rsa, bool is_public, RSATask task, const unsigned char *input, unsigned short int input_len,
            unsigned char *output);

void freeRSA(RSA *rsa);

#endif //RANSOMWARE_RSA_H
