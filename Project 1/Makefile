.PHONY: all clean

CC = clang
CFLAGS = -Wall -O0 -ggdb -pipe -std=c99 -fno-stack-protector
LDFLAGS = -lssl -lcrypto -Wl,-z,execstack

all: prset01

clean:
	rm -f prset01
