CC = gcc
CFLAGS = -Wall -Wextra

main: main.c
	$(CC) $(CFLAGS) -o netbox main.c

clean:
	rm -f netbox
