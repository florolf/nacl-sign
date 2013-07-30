LDFLAGS=-lsodium
CFLAGS=-Wall -Werror -g

all: kp check

kp: kp.o

check: check.o

clean:
	rm -f *.o kp check
