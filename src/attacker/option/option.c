#include "option.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>

#define REGEX_IPV4_EXPRESSION "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

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
    regex_t regex;

    switch (*opt) {
        case IP:
            if (regcomp(&regex, REGEX_IPV4_EXPRESSION, REG_EXTENDED) != 0)
                return false;

            if (regexec(&regex, value, 0, NULL, 0) != 0) {
                regfree(&regex);
                return false;
            }

            regfree(&regex);

            break;
        case PORT:
            for (unsigned int i = 0; i < strlen(value); i++)
                if (!isdigit(value[i]))
                    return false;
            break;
    }

    return true;
}

/**
 * Display the help.
 */
void help(void) {
    fputs("Program's arguments:\n"
          "\t-ip [ip]\n"
          "\t\tIp of the server.\n"
          "\t\tValid IPV4 address.\n"
          "\t\tNOT NULL | ONCE\n"
          "\t-port [port]\n"
          "\t\tPort of the server.\n"
          "\t\tNumber only.\n"
          "\t\tNOT NULL | ONCE\n", stdout);
}