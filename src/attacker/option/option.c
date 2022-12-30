#include "option.h"

#include <stdio.h>
#include <string.h>

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