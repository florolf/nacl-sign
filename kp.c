#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "crypto_sign.h"

unsigned char pk[crypto_sign_PUBLICKEYBYTES];
unsigned char sk[crypto_sign_SECRETKEYBYTES];

static void print_hex(const unsigned char *data, size_t len) {
	while(len--)
		printf("%02hhx", *data++);

	putchar('\n');
}

int main(int argc, char **argv) {
	memset(pk, 0, crypto_sign_PUBLICKEYBYTES);
	memset(sk, 0, crypto_sign_SECRETKEYBYTES);

	crypto_sign_keypair(pk, sk);

	printf("PK (%d bytes): ", crypto_sign_PUBLICKEYBYTES);
	print_hex(pk, crypto_sign_PUBLICKEYBYTES);

	printf("SK (%d bytes): ", crypto_sign_SECRETKEYBYTES);
	print_hex(sk, crypto_sign_SECRETKEYBYTES);

	return EXIT_SUCCESS;
}
