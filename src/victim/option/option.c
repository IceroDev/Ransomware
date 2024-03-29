#include "option.h"

#include <stdio.h>
#include <string.h>

#include "../../lib/key/key_set.h"
#include "../../lib/tcp/tcp.h"
#include "../../lib/util/tool.h"

/**
 * Parse an `Option` into a string.
 * @param opt Option to parse (Option)
 * @return The parsed `Option` into a string (const char *)
 */
const char *optionToString(const unsigned short int *opt) {
    const char *str;

    switch (*opt) {
        case HELP:
            str = "--help";
            break;
        case DIRECTORY:
            str = "-d";
            break;
        case KEY:
            str = "-key";
            break;
        case IV:
            str = "-iv";
            break;
        case IP:
            str = "-ip";
            break;
        case PORT:
            str = "-port";
            break;
    }

    return str;
}

/**
 * Parse an `Option` from a string`.
 * @param str String to parse (const char *)
 * @return Integer to indicate the success or not (const short int)
 * -1 = Failed to parse the string into an `Option`.
 * > 0 `Option` parsed.
 */
short int optionFromString(const char *str) {
    for (unsigned short int opt = 0; opt < OPTION_SIZE; opt++)
        if (strcmp(optionToString(&opt), str) == 0)
            return (short int) opt;

    return -1;
}

/**
 * Validate an option.
 * @param opt Type of option (const unsigned short int *)
 * @param value Value to check (const char *)
 * @return Boolean to indicate if the value is valid or not. True if validated, false otherwise (bool)
 */
bool validateOption(const unsigned short int *opt, const char *value) {
    switch (*opt) {
        case DIRECTORY:
            if (value[strlen(value) - 1] == '/')
                return false;
            break;
        case KEY:
            if (strlen(value) != 2 * AES_256_KEY_SIZE)
                return false;
            break;
        case IV:
            if (strlen(value) != 2 * AES_BLOCK_SIZE)
                return false;
            break;
        case IP:
            if (!isIPV4valid(value))
                return false;
            break;
        case PORT:
            if (!isFullDigit(value))
                return false;
            break;
    }

    return true;
}

/**
 * Display the help.
 */
void help(void) {
    fprintf(stdout,
            "Program's arguments:\n"
            "\t-d [path]\n"
            "\t\tDirectory to encrypt/decrypt.\n"
            "\t\tCannot end with '/'.\n"
            "\t\tREQUIRED | NOT NULL\n"
            "\t-key [key]\n"
            "\t\tKey to decrypt the directories.\n"
            "\t\tShould be 64 characters.\n"
            "\t\tNOT NULL | ONCE\n"
            "\t-iv [iv]\n"
            "\t\tIv to decrypt the directories.\n"
            "\t\tShould be 32 characters.\n"
            "\t\tNOT NULL | ONCE\n"
            "\t-ip [ip]\n"
            "\t\tIp of the server.\n"
            "\t\tValid IPV4 address. Default value is: %s\n"
            "\t\tNOT NULL | ONCE\n"
            "\t-port [port]\n"
            "\t\tPort of the server.\n"
            "\t\tNumber only & port >= 1024. Default value is: %d.\n"
            "\t\tNOT NULL | ONCE\n",
            TCP_SERVER_IP, TCP_SERVER_PORT);
}