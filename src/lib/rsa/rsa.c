#include "rsa.h"

#include <openssl/ossl_typ.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

/**
 * Create a new RSA structure.
 * @param key RSA key to use (char *)
 * @param is_public Indicate if the RSA key is public or not (bool)
 * @return RSA structure created (RSA *)
 */
RSA *newRSA(char *key, const bool is_public) {
    RSA *rsa = NULL;
    BIO *key_bio = BIO_new_mem_buf(key, -1);

    if (key_bio == NULL)
        return NULL;

    if (is_public)
        rsa = PEM_read_bio_RSA_PUBKEY(key_bio, &rsa, NULL, NULL);
    else
        rsa = PEM_read_bio_RSAPrivateKey(key_bio, &rsa, NULL, NULL);

    BIO_free_all(key_bio);

    return rsa;
}

/**
 * Encrypt or decrypt a input with RSA.
 * @param rsa RSA structure used for the operation (RSA *)
 * @param is_public Indicate if the RSA key is public or not (bool)
 * @param task `RSA_Task` to perform (RSATask)
 * @param input Input to encrypt/decrypt in bytes (const unsigned char *)
 * @param input_len Length of the input (const unsigned short int)
 * @param output Output of the encrypt/decrypt task in bytes (unsigned char *)
 * @return Length of the output (-1 if error) (int)
 */
int
rsaTask(RSA *rsa, const bool is_public, RSATask task, const unsigned char *input, const unsigned short int input_len,
        unsigned char *output) {
    int output_size;

    switch (task) {
        case RSA_ENCRYPT:
            if (is_public)
                output_size = RSA_public_encrypt(input_len, input, output, rsa, RSA_PKCS1_OAEP_PADDING);
            else
                output_size = RSA_private_encrypt(input_len, input, output, rsa, RSA_PKCS1_OAEP_PADDING);
            break;
        case RSA_DECRYPT:
            if (is_public)
                output_size = RSA_public_decrypt(input_len, input, output, rsa, RSA_PKCS1_OAEP_PADDING);
            else
                output_size = RSA_private_decrypt(input_len, input, output, rsa, RSA_PKCS1_OAEP_PADDING);
            break;
    }

    return output_size;
}

void freeRSA(RSA *rsa) {
    RSA_free(rsa);
}

#pragma GCC diagnostic pop