#ifndef RANSOMWARE_KEY_SET_H
#define RANSOMWARE_KEY_SET_H

#include <stdbool.h>
#include <stddef.h>

#include "../rsa/rsa.h"

// 32 byte key (256-bit key)
#define AES_256_KEY_SIZE 32
// 16 byte block size (128-bit)
#define AES_BLOCK_SIZE 16

#define free_key_set_macro(key_set) ({ \
free((key_set)->key);                  \
free((key_set)->iv);                   \
free((key_set));                       \
})

typedef struct KeySet {
    unsigned char *key;
    unsigned char *iv;
} KeySet;

KeySet *newEmptyKeySet(size_t key_size, size_t block_size);

bool generateKeySet(const KeySet *key_set);

void parseKeySet(KeySet *key_set, unsigned char *key, size_t key_size, unsigned char *iv, size_t block_size);

KeySet *newEncryptedKeySet(const KeySet *key_set, RSA *rsa, bool is_public);

KeySet *newDecryptedKeySet(const KeySet *key_set, RSA *rsa, bool is_public);

void eraseKeySet(const KeySet *key_set);

#endif //RANSOMWARE_KEY_SET_H
