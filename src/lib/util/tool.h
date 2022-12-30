#ifndef RANSOMWARE_TOOL_H
#define RANSOMWARE_TOOL_H

#include <stdbool.h>

// 32 characters
#define MACHINE_ID_SIZE 32

#define get_size_macro(element) ((const unsigned short int)(sizeof((element)) / sizeof((element)[0])))

char *byteToHex(const unsigned char *bytes, unsigned short int size);

unsigned char *hexToByte(const char *hex);

char *getMachineID(void);

bool addPublicKey(void);

bool isIPV4valid(const char *ipv4_address);

bool isFullDigit(const char *str);

#endif //RANSOMWARE_TOOL_H
