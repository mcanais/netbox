CC = gcc
CFLAGS = -Wall -Wextra

main: main.c netbox.c netbox.h
	$(CC) $(CFLAGS) -o netbox main.c netbox.c

clean:
	rm -f netbox
