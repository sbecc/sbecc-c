#include "sbecc.c"
#include <inttypes.h>
#include <stdio.h>

int main()
{
	uint8_t bytes[100];
	sbecc_encrypt(bytes, 32);
	return 0;
}