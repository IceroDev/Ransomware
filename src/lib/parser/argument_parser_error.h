#ifndef RANSOMWARE_ARGUMENT_PARSER_ERROR_H
#define RANSOMWARE_ARGUMENT_PARSER_ERROR_H

#include "argument.h"

typedef enum ArgumentParserError {
    MEMORY_ALLOCATION_FAIL = -1,
    UNSUPPORTED = -2,
    VALUE_NULL = -3,
    ONCE = -4,
    REQUIRED = -5,
    INVALID_VALUE = -6,
} ArgumentParserError;

void displayParseArgumentErrorMeaning(char *argv[],
                                      const Argument *arguments,
                                      const ArgumentParserError *error,
                                      const char *(*f_optionToString)(const unsigned short int *opt));

#endif //RANSOMWARE_ARGUMENT_PARSER_ERROR_H
