CC ?= cc
AR ?= ar
CFLAGS ?= -O2 -Wall -Wextra

all: libwsio.a

wsio.o: wsio.c
	$(CC) $(CFLAGS) -c wsio.c -o wsio.o

libwsio.a: wsio.o
	$(AR) rcs libwsio.a wsio.o

clean:
	rm -f wsio.o libwsio.a

.PHONY: all clean
