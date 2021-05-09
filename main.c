#include "sbecc.c"
#include <stdio.h>

int main()
{
	unsigned char header[76];
	unsigned char script[] = "print(\"Hello, world!\")";
	sbecc_create_context();
	sbecc_encrypt(header, sizeof(header), script, sizeof(script));
	sbecc_destroy_context();

	size_t i;
	for (i = 0; i < sizeof(header); ++i)
	{
		printf("%02hhx", header[i]);
	}

	for (i = 0; i < sizeof(script); ++i)
	{
		printf("%02hhx", script[i]);
	}

	printf("\n");

	return 0;
}