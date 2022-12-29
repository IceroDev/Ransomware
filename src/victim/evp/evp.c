#include "evp.h"

#include <openssl/err.h>
#include <string.h>

#include "../../lib/util/tool.h"

#define FILE_EXTENSION ".2js"

#define create_buffer_or_return_macro(buffer, size) ({ \
if ((size) > FILENAME_MAX)                             \
    return NULL;                                       \
(buffer) = (char *) malloc((size) * sizeof(char));     \
                                                       \
if ((buffer) == NULL) {                                \
    return NULL;                                       \
}                                                      \
})

const unsigned short int EXTENSION_SIZE = strlen(FILE_EXTENSION);

const char *const EXCLUSIONS[] = {FILE_EXTENSION, ".mp4", ".mov", ".avi", ".wmv"};
const unsigned short int EXCLUSIONS_SIZE = get_size_macro(EXCLUSIONS);

/**
 * Display error from OpenSSL.
 */
void displayOpensslError(void) {
    ERR_print_errors_fp(stderr);
}

/**
 * Determine if a file should be processed.
 * @param path Path to verify (const char *)
 * @param task Current `EvpTask` running (const EvpTask *)
 * @return True if the file should be processed, false otherwise (bool)
 */
inline bool process(const char *path, const EvpTask *task) {
    const char *tmp;

    switch (*task) {
        case Evp_ENCRYPT:
            for (unsigned short int i = 0; i < EXCLUSIONS_SIZE; i++) {
                const char *exclusion = EXCLUSIONS[i];
                tmp = strstr(path, exclusion);

                if (tmp != NULL && strlen(tmp) == strlen(exclusion))
                    return false;
            }
            break;
        case Evp_DECRYPT:
            tmp = strstr(path, FILE_EXTENSION);
            if (tmp == NULL || strlen(tmp) != EXTENSION_SIZE)
                return false;
            break;
    }

    return true;
}

/**
 * Parse a task into a string.
 * @param task `EvpTask` to parse (const EvpTask *)
 * @return The parsed `TASK` into a string (const char *)
 */
inline const char *taskToString(const EvpTask *task) {
    const char *str;

    switch (*task) {
        case Evp_ENCRYPT:
            str = "encrypt";
            break;
        case Evp_DECRYPT:
            str = "decrypt";
            break;
    }

    return str;
}

/**
 * Build the path of the output file based on the `TASK` and the input path.
 * @param path Input path (const char *)
 * @param task Current `EvpTask` running (const EvpTask *)
 * @return The path build. (char *)
 * May return null if it can't allocate memory or if the path size exceed the max path length.
 */
inline char *getTaskPath(const char *path, const EvpTask *task) {
    char *task_path;

    {
        const unsigned short int path_size = strlen(path);
        // size = path_size + '\0'
        unsigned short int size = path_size + 1;

        switch (*task) {
            case Evp_ENCRYPT:
                size += EXTENSION_SIZE;
                create_buffer_or_return_macro(task_path, size);
                snprintf(task_path, size, "%s%s", path, FILE_EXTENSION);
                break;
            case Evp_DECRYPT:
                size -= EXTENSION_SIZE;
                create_buffer_or_return_macro(task_path, size);
                memcpy(task_path, path, size - 1);
                task_path[size - 1] = '\0';
                break;
        }

    }

    return task_path;
}

/**
 *
 * @param file_in Input File (File *)
 * @param file_out Output File (File *)
 * @param key_set `KeySet` containing the key and the iv (const KeySet *)
 * @param f_EVP_Init_ex EVP init function for the current `EvpTask` (int (f)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv))
 * @param f_EVP_Update EVP update function for the current `EvpTask` (int (f)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl))
 * @param f_EVP_Final_ex EVP final function for the current `EvpTask` (int (f_EVP_Final_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl))
 * @param buffer_reader_size Size to use for the buffer reader (const EvpBufferSize *)
 * @param buffer_writer_size Size to use for the buffer writer (const EvpBufferSize *)
 * @return Success of the operation (bool)
 */
extern inline bool evp(FILE *file_in, FILE *file_out, const KeySet *key_set,
                       int (f_EVP_Init_ex)(EVP_CIPHER_CTX *ctx,
                                           const EVP_CIPHER *cipher, ENGINE *impl,
                                           const unsigned char *key,
                                           const unsigned char *iv),
                       int (f_EVP_Update)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                          int *outl, const unsigned char *in, int inl),
                       int (f_EVP_Final_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                            int *outl),
                       const EvpBufferSize *buffer_reader_size, const EvpBufferSize *buffer_writer_size) {
    EVP_CIPHER_CTX *ctx;

    // Create and initialise the context.
    if (!(ctx = EVP_CIPHER_CTX_new())) {
        displayOpensslError();
        return false;
    }

    // Initialise the decryption operation.
    if (1 != f_EVP_Init_ex(ctx, EVP_aes_256_cbc(), NULL, key_set->key, key_set->iv)) {
        displayOpensslError();
        EVP_CIPHER_CTX_free(ctx);
        return false;
    }

    {
        unsigned char buffer_reader[*buffer_reader_size];
        unsigned short int read_size;

        unsigned char buffer_writer[*buffer_writer_size];
        int output_len;

        do {
            read_size = fread(buffer_reader, sizeof(unsigned char), *buffer_reader_size, file_in);

            // Provide the buffer reader to be encrypted, and obtain the encrypted output in the buffer writer.
            if (1 != f_EVP_Update(ctx, buffer_writer, &output_len, buffer_reader, read_size)) {
                displayOpensslError();
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }

            // Ensure that we have wrote the whole output in the file.
            if (fwrite(buffer_writer, sizeof(unsigned char), output_len, file_out) != output_len) {
                EVP_CIPHER_CTX_free(ctx);
                return false;
            }
        } while (read_size == *buffer_reader_size);

        // Finalise the encryption. Further ciphertext bytes may be written at this stage.
        if (1 != f_EVP_Final_ex(ctx, buffer_writer, &output_len)) {
            displayOpensslError();
            EVP_CIPHER_CTX_free(ctx);
            return false;
        }

        EVP_CIPHER_CTX_free(ctx);

        // Ensure that we have wrote the whole output in the file.
        if (fwrite(buffer_writer, sizeof(unsigned char), output_len, file_out) != output_len)
            return false;
    }

    return true;
}

/**
 * Encrypt or decrypt a file.
 * @param key_set `KeySet` containing the key and the iv (const KeySet *)
 * @param path_in Path of the input file (const char *)
 * @param path_out Path of the output file (const char *)
 * @param f_EVP_Init_ex EVP init function for the current `EvpTask` (int (f)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv))
 * @param f_EVP_Update EVP update function for the current `EvpTask` (int (f)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl))
 * @param f_EVP_Final_ex EVP final function for the current `EvpTask` (int (f_EVP_Final_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl))
 * @param buffer_reader_size Size to use for the buffer reader (const EvpBufferSize *)
 * @param buffer_writer_size Size to use for the buffer writer (const EvpBufferSize *)
 * @return Success of the task (bool)
 */
inline bool evpTask(const KeySet *key_set, const char *path_in, const char *path_out,
                    int (f_EVP_Init_ex)(EVP_CIPHER_CTX *ctx,
                                        const EVP_CIPHER *cipher, ENGINE *impl,
                                        const unsigned char *key,
                                        const unsigned char *iv),
                    int (f_EVP_Update)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                       int *outl, const unsigned char *in, int inl),
                    int (f_EVP_Final_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                         int *outl),
                    const EvpBufferSize *buffer_reader_size, const EvpBufferSize *buffer_writer_size) {
    FILE *file_in, *file_out;

    if ((file_in = fopen(path_in, "r")) == NULL)
        return false;

    if ((file_out = fopen(path_out, "w+")) == NULL) {
        fclose(file_in);
        return false;
    }

    if (!evp(file_in, file_out, key_set, f_EVP_Init_ex, f_EVP_Update, f_EVP_Final_ex, buffer_reader_size,
             buffer_writer_size)) {
        fclose(file_in);
        fclose(file_out);
        return false;
    }

    fclose(file_in);
    fclose(file_out);

    return true;
}