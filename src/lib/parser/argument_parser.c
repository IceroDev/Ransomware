#include "argument_parser.h"

#include <malloc.h>
#include <string.h>

#include "argument_parser_error.h"

bool isValuePresent(const unsigned short int *value, const unsigned short int *p, const unsigned short int *p_size);

bool addArgument(Argument **arguments, short int *counter, Argument argument);

ArgumentParserError setArgumentError(Argument **arguments, Argument argument, ArgumentParserError error);

/**
 * Parse & validate the program's arguments. If "--help" is a supported option, it will return it with a NULL value.
 * @param arguments Pointer to add the arguments (Argument **)
 * @param argc Number of program's arguments (const int *)
 * @param argv Program's arguments (char * [])
 * @param f_optionFromString Function to parse an option from a string (short int (*f)(const char *str))
 * @param f_validateOption Function to validate the option (bool (*f)(const unsigned short int *opt, const char *value))
 * @param arg_value_null Pointer containing all option that can have a NULL value (const unsigned short int *)
 * @param arg_value_null_size Size of arg_value_null (const unsigned short int)
 * @param arg_once Pointer containing all option that can be only present once (const unsigned short int *)
 * @param arg_once_size Size of arg_once (const unsigned short int)
 * @param arg_required Pointer containing all option required (const unsigned short int *)
 * @param arg_required_size Size of arg_required (const unsigned short int)
 * @return An integer to determine and the parse was successful or not (short int)
 * > 0 indicates the number of parsed arguments, meaning the length of arguments.
 * 0 indicates that no argument has been found OR the help argument has been detected.
 * < 0 indicates an error, use `displayParseArgumentErrorMeaning` to display the reason.
 */
short int parseArguments(Argument **arguments,
                         const int *argc, char *argv[],
                         short int (*f_optionFromString)(const char *str),
                         bool (*f_validateOption)(const unsigned short int *opt, const char *value),
                         const unsigned short int *arg_value_null, const unsigned short int arg_value_null_size,
                         const unsigned short int *arg_once, const unsigned short int arg_once_size,
                         const unsigned short int *arg_required, const unsigned short int arg_required_size) {
    short int counter = 0;

    const bool is_set_arg_value_null = arg_value_null != NULL;
    const bool is_set_arg_once = arg_once != NULL;

    unsigned short int *once = NULL;
    unsigned short int once_size = 0;

    // Skip the first element (the name of the program).
    for (unsigned short int i = 1; i < *argc; i++) {
        const short int tmp = f_optionFromString(argv[i]);

        if (tmp == -1) {
            free(once);
            return setArgumentError(arguments, newArgument(i, NULL), UNSUPPORTED);
        }

        // Since f_optionFromString should return -1 if a string cannot be converted to an `Option`, the cast is safe
        // due to the condition above.
        const unsigned short int option = (const unsigned short int) tmp;

        // Special case for the help detected.
        if (strncmp("--help", argv[i], 6) == 0) {
            free(once);
            counter = 0;

            if (!addArgument(arguments, &counter, newArgument(option, NULL)))
                return MEMORY_ALLOCATION_FAIL;

            return counter;
        }

        if (is_set_arg_once) {
            if (isValuePresent(&option, arg_once, &arg_once_size) &&
                isValuePresent(&option, once, &once_size)) {
                free(once);
                return setArgumentError(arguments, newArgument(option, NULL), ONCE);
            }

            once_size++;
            once = (unsigned short int *) realloc(once, once_size * sizeof(const unsigned short int));

            if (once == NULL) {
                *arguments = NULL;
                return MEMORY_ALLOCATION_FAIL;
            }

            once[once_size - 1] = option;
        }

        char *value = NULL;

        if (!(is_set_arg_value_null && isValuePresent(&option, arg_value_null, &arg_value_null_size))) {
            i++;

            if (i < *argc && f_optionFromString(argv[i]) == -1) {
                value = argv[i];

                if (!f_validateOption(&option, value)) {
                    free(once);
                    return setArgumentError(arguments, newArgument(option, value), INVALID_VALUE);
                }

            } else {
                free(once);
                return setArgumentError(arguments, newArgument(option, NULL), VALUE_NULL);
            }
        }

        if (!addArgument(arguments, &counter, newArgument(option, value))) {
            free(once);
            return MEMORY_ALLOCATION_FAIL;
        }
    }

    // No longer need of free for the final check.
    free(once);

    // Check if the required arguments are present.
    for (unsigned short int i = 0; i < arg_required_size; i++) {
        bool found = false;

        for (unsigned short int j = 0; j < counter; j++)
            if (arg_required[i] == (&(*arguments)[j])->option) {
                found = true;
                break;
            }

        if (!found)
            return setArgumentError(arguments, newArgument(arg_required[i], NULL), REQUIRED);
    }

    return counter;
}

/**
 * Check if a value is present in a pointer.
 * @param value Value to look for (const unsigned short int *)
 * @param p Pointer to check (const unsigned short int *)
 * @param p_size Size of the pointer (const unsigned short int *)
 * @return A boolean to indicate if the value has been found in the pointer (true) or not (false) (bool)
 */
bool isValuePresent(const unsigned short int *value, const unsigned short int *p, const unsigned short int *p_size) {
    for (unsigned short int i = 0; i < *p_size; i++)
        if (*value == p[i])
            return true;

    return false;
}

/**
 * Add an `Argument` in the pointer containing all `Argument`.
 * @param arguments Pointer containing all `Argument` found by the parser (Argument **)
 * @param counter Current size of arguments (short int *)
 * @param argument `Argument` to add (const Argument)
 * @return A boolean to indicate if the `Argument` has been added (true) or not (false) (bool)
 */
bool addArgument(Argument **arguments, short int *counter, const Argument argument) {
    (*counter)++;

    *arguments = (Argument *) realloc(*arguments, *counter * sizeof(Argument));

    if (arguments == NULL)
        return false;

    (*arguments)[*counter - 1] = argument;

    return true;
}

/**
 * Clear the main pointer of `Argument` and set it to indicate a parse error.
 * @param arguments Pointer containing all `Argument` found by the parser (Argument **)
 * @param argument `Argument` that raised the error (Argument)
 * @param error Error encountered (ArgumentParserError)
 * @return Error encountered (ArgumentParserError)
 * If the pointer cannot be set to indicate the error, MEMORY_ALLOCATION_FAIL will be returned.
 */
ArgumentParserError setArgumentError(Argument **arguments, const Argument argument, ArgumentParserError error) {
    *arguments = (Argument *) realloc(*arguments, 1 * sizeof(Argument));

    if (arguments == NULL)
        return MEMORY_ALLOCATION_FAIL;

    (*arguments)[0] = argument;

    return error;
}