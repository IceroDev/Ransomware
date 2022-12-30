#ifndef RANSOMWARE_OPTION_H
#define RANSOMWARE_OPTION_H

#include <stdbool.h>

#define OPTION_SIZE 3

typedef enum Option {
    HELP,
    IP,
    PORT,
} Option;

const char *optionToString(const unsigned short int *opt);

short int optionFromString(const char *str);

bool validateOption(const unsigned short int *opt, const char *value);

void help(void);

#endif //RANSOMWARE_OPTION_H
