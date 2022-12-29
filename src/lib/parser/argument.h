#ifndef RANSOMWARE_ARGUMENT_H
#define RANSOMWARE_ARGUMENT_H

typedef struct Argument {
    unsigned short int option;
    const char *value;
} Argument;

Argument newArgument(unsigned short int option, const char *value);

#endif //RANSOMWARE_ARGUMENT_H
