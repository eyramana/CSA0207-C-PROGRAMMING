CC     ?= gcc
CFLAGS ?= -std=c99 -O2 -Wall -Wextra -Wpedantic

steg: src/steg.c
	$(CC) $(CFLAGS) -o $@ $<

test: steg
	./steg encode samples/input.bmp /tmp/encoded.bmp "It is a secret!!"
	./steg decode /tmp/encoded.bmp

clean:
	rm -f steg

.PHONY: test clean
