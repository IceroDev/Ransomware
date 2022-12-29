#include "argument_parser_error.h"

#include <stdio.h>

/**
 * Display the error raised by the parser.
 * @param argv Program's arguments (char * [])
 * @param arguments Pointer containing the argument that raised the error (const Argument **)
 * @param error Error raised by the parser (const ArgumentParserError)
 * @param f_optionToString Function to parse an option into a string (const char *(*f)(const unsigned short int *opt))
 */
void displayParseArgumentErrorMeaning(char *argv[],
                                      const Argument *arguments,
                                      const ArgumentParserError *error,
                                      const char *(*f_optionToString)(const unsigned short int *opt)) {
    switch (*error) {
        case MEMORY_ALLOCATION_FAIL:
            fputs("Failed to allocate the arguments.\n", stderr);
            break;
        case UNSUPPORTED:
            fprintf(stderr, "Unsupported argument %s.\n", argv[(&arguments[0])->option]);
            break;
        case VALUE_NULL:
            fprintf(stderr, "Argument %s cannot have a null value.\n", f_optionToString(&(&arguments[0])->option));
            break;
        case ONCE:
            fprintf(stderr, "Argument %s can only be present once.\n", f_optionToString(&(&arguments[0])->option));
            break;
        case REQUIRED:
            fprintf(stderr, "Missing required argument %s.\n", f_optionToString(&(&arguments[0])->option));
            break;
        case INVALID_VALUE:
            fprintf(stderr, "Argument %s has an invalid value %s.\n", f_optionToString(&(&arguments[0])->option),
                    (&arguments[0])->value);
            break;
    }
}
