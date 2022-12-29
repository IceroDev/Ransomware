#include "key_set.h"

#include <openssl/rand.h>
#include <memory.h>

/**
 * Create a new empty `KeySet`.
 * @param key_size Bytes size of the key (size_t)
 * @param iv_size Bytes size of the iv (size_t)
 * @return An empty `KeySet` (KeySet *)
 * May return null if it fails to allocate memory.
 */
KeySet *newEmptyKeySet(size_t key_size, size_t block_size) {
    KeySet *key_set = (KeySet *) malloc(sizeof(KeySet));
    key_set->key = (unsigned char *) malloc(key_size);
    key_set->iv = (unsigned char *) malloc(block_size);

    if (key_set == NULL || key_set->key == NULL || key_set->iv == NULL) {
        free_key_set_macro(key_set);
        return NULL;
    }

    return key_set;
}

/**
 * Generate a key and an iv for the `KeySet`. Only for a `KeySet` with a AES_256_KEY_SIZE & AES_BLOCK_SIZE.
 * @param key_set `KeySet` that will contain the key and the iv (KeySet *)
 * @return Success of the generation (bool)
 */
bool generateKeySet(const KeySet *key_set) {
    return RAND_bytes(key_set->key, AES_256_KEY_SIZE) == 1 && RAND_bytes(key_set->iv, AES_BLOCK_SIZE) == 1;
}

/**
 * Parse byte format of the key and the iv into a `KeySet`.
 * @param key_set KeySet` that will contain the key and the iv (KeySet *)
 * @param key Key (unsigned char *)
 * @param key_size Bytes size of the key (size_t)
 * @param iv Iv (unsigned char *)
 * @param iv_size Bytes size of the iv (size_t)
 */
void parseKeySet(KeySet *key_set, unsigned char *key, size_t key_size, unsigned char *iv, size_t iv_size) {
    memcpy(key_set->key, key, key_size);
    memcpy(key_set->iv, iv, iv_size);
}

/**
 * Create a new encrypted `KeySet` from an existing `KeySet` with RSA.
 * @param key_set `KeySet` to encrypt (const KeySet *)
 * @param rsa RSA structure used for the encryption (RSA *)
 * @param is_public True if the encryption is made with the public RSA key, false otherwise (const bool)
 * @retun New encrypted `KeySet` (KeySet *)
 * Can be null if it can't allocate the memory or if the encryption fails.
 */
KeySet *newEncryptedKeySet(const KeySet *key_set, RSA *rsa, const bool is_public) {
    KeySet *encrypted_key_set = newEmptyKeySet(RSA_ENCRYPTION_SIZE, RSA_ENCRYPTION_SIZE);

    if (encrypted_key_set == NULL)
        return NULL;

    int encrypted_size = 0;

    encrypted_size += rsaTask(rsa, is_public, RSA_ENCRYPT, key_set->key, AES_256_KEY_SIZE, encrypted_key_set->key);
    encrypted_size += rsaTask(rsa, is_public, RSA_ENCRYPT, key_set->iv, AES_BLOCK_SIZE, encrypted_key_set->iv);

    if (encrypted_size != 2 * RSA_ENCRYPTION_SIZE) {
        free_key_set_macro(encrypted_key_set);
        return NULL;
    }

    return encrypted_key_set;
}

/**
 * Create a new decrypted `KeySet` from an encrypted `KeySet` with RSA.
 * @param key_set `KeySet` to decrypt (const KeySet *)
 * @param rsa RSA structure used for the decryption (RSA *)
 * @param is_public True if the decryption is made with the public RSA key, false otherwise (const bool)
 * @return New decrypted `KeySet` (KeySet *)
 * Can be null if it can't allocate the memory or if the decryption fails.
 */
KeySet *newDecryptedKeySet(const KeySet *key_set, RSA *rsa, const bool is_public) {
    // Reserve 256 bytes for the key and the iv. They will be resized later.
    KeySet *decrypted_key_set = newEmptyKeySet(RSA_ENCRYPTION_SIZE, RSA_ENCRYPTION_SIZE);

    if (decrypted_key_set == NULL)
        return NULL;

    int decrypted_size = 0;

    decrypted_size += rsaTask(rsa, is_public, RSA_DECRYPT, key_set->key, RSA_ENCRYPTION_SIZE, decrypted_key_set->key);
    decrypted_size += rsaTask(rsa, is_public, RSA_DECRYPT, key_set->iv, RSA_ENCRYPTION_SIZE, decrypted_key_set->iv);

    // Resize the key and the iv (32 & 16).
    if (decrypted_size != AES_256_KEY_SIZE + AES_BLOCK_SIZE ||
        (decrypted_key_set->key = (unsigned char *) realloc(decrypted_key_set->key, AES_256_KEY_SIZE)) == NULL ||
        (decrypted_key_set->iv = (unsigned char *) realloc(decrypted_key_set->iv, AES_BLOCK_SIZE)) == NULL) {
        free_key_set_macro(decrypted_key_set);
        return NULL;
    }

    return decrypted_key_set;
}

/**
 * Erase the key and the iv from the memory. Only for a `KeySet` with a AES_256_KEY_SIZE & AES_BLOCK_SIZE.
 * @param key_set `KeySet` to erase (KeySet *)
 */
void eraseKeySet(const KeySet *key_set) {
    memset(key_set->key, 0, AES_256_KEY_SIZE);
    memset(key_set->iv, 0, AES_BLOCK_SIZE);
}