#define USE_BASIC_CONFIG true
#include "secp256k1/include/secp256k1.h"

// Public keys:
// 04f9677f2dcfa326d5339a247c5ae00b1161fbc6207e37d0ab45da45c1475f28385d9a853b61df9dd34b54b2fea3cd189b9bbbeb1d391c69ab17dec505acdbd859
// 03f9677f2dcfa326d5339a247c5ae00b1161fbc6207e37d0ab45da45c1475f2838

unsigned char server_pub_key[65] = {4, 249, 103, 127, 45, 207, 163, 38, 213, 51, 154, 36, 124, 90, 224, 11, 17, 97,
									251, 198, 32, 126, 55, 208, 171, 69, 218, 69, 193, 71, 95, 40, 56, 93, 154, 133,
									59, 97, 223, 157, 211, 75, 84, 178, 254, 163, 205, 24, 155, 155, 187, 235, 29, 57,
									28, 105, 171, 23, 222, 197, 5, 172, 219, 216, 89};

int sbecc_create_context();
int sbecc_encrypt(unsigned char *header, size_t header_size, unsigned char *script, size_t script_size);
int sbecc_destroy_context();
