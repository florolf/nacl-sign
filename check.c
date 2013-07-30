#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "sodium.h"

unsigned char pk[crypto_sign_PUBLICKEYBYTES];
unsigned char sk[crypto_sign_SECRETKEYBYTES];

static void read_hex(unsigned char *out, size_t len, const char *hex) {
	assert(strlen(hex) % 2 == 0);
	assert(strlen(hex) / 2 == len);

	while(len--) {
		char tmp[3];

		tmp[0] = *hex++;
		tmp[1] = *hex++;
		tmp[2] = 0;

		sscanf(tmp, "%hhx", out++);
	}
}

static int dosign(void *area, size_t size) {
	int ret = -1;
	void *out = malloc(size + crypto_sign_BYTES);
	assert(out);

	unsigned long long smlen;
	if(crypto_sign(out, &smlen, area, size, sk) < 0) {
		fprintf(stderr, "signing failed\n");
		goto out;
	}

	void *tmp = out;
	while(smlen--)
		putchar(*(unsigned char*)tmp++);

	ret = 0;

out:
	free(out);
	return ret;
}

static int doverify(void *area, size_t size) {
	int ret = -1;
	void *out = malloc(size);
	assert(out);

	unsigned long long mlen;
	if(crypto_sign_open(out, &mlen, area, size, pk) < 0) {
		fprintf(stderr, "validation failed\n");
		goto out;
	}

	ret = 0;

out:
	free(out);
	return ret;
}

int main(int argc, char **argv) {
	if(argc != 4) {
		fprintf(stderr, "usage: %s [sign|check] key file\n", argv[0]);
		return EXIT_FAILURE;
	}

	sodium_init();

	if(!strcmp(argv[1], "sign"))
		read_hex(sk, crypto_sign_SECRETKEYBYTES, argv[2]);
	else if(!strcmp(argv[1], "check"))
		read_hex(pk, crypto_sign_PUBLICKEYBYTES, argv[2]);
	else {
		fprintf(stderr, "unknown operation %s\n", argv[1]);
		return EXIT_FAILURE;
	}

	int fd = open(argv[3], O_RDONLY);
	if(fd < 0) {
		perror("open");
		return EXIT_FAILURE;
	}

	struct stat s;
	if(fstat(fd, &s) < 0) {
		perror("stat");
		return EXIT_FAILURE;
	}

	void *area = mmap(NULL, s.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if(!area) {
		perror("mmap");
		return EXIT_FAILURE;
	}

	if(!strcmp(argv[1], "sign")) {
		if(dosign(area, s.st_size) < 0)
			return EXIT_FAILURE;

		return EXIT_SUCCESS;
	} else {
		if(doverify(area, s.st_size) < 0)
			return EXIT_FAILURE;

		return EXIT_SUCCESS;
	}
}
