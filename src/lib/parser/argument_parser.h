#ifndef RANSOMWARE_ARGUMENT_PARSER_H
#define RANSOMWARE_ARGUMENT_PARSER_H

#include "argument.h"

#include <stdbool.h>

short int parseArguments(Argument **arguments,
                         const int *argc, char *argv[],
                         short int (*f_optionFromString)(const char *str),
                         bool (*f_validateOption)(const unsigned short int *opt, const char *value),
                         const unsigned short int *arg_value_null, unsigned short int arg_value_null_size,
                         const unsigned short int *arg_once, unsigned short int arg_once_size,
                         const unsigned short int *arg_required, unsigned short int arg_required_size);

#endif //RANSOMWARE_ARGUMENT_PARSER_H
