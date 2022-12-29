#include "argument.h"

/**
 * Create a new `Argument`.
 * @param option Option of the `Argument` (const unsigned short int)
 * @param value Value of the `Argument` (const char *)
 * @return
 */
Argument newArgument(const unsigned short int option, const char *value) {
    Argument argument = {option, value};
    return argument;
}