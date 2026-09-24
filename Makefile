CC = gcc
CFLAGS = -Wall -Wextra

all: code/main.c code/netbox.c code/netbox.h code/result.h
	$(CC) $(CFLAGS) -o netbox code/main.c code/netbox.c

clean:
	rm -f netbox

.PHONY: all clean
