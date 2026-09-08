#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef struct netbox_state {
	char* username;
	char* password;
	int peer_port;
	// Possivelmente sockets de tcp/udp?
	
} netbox_state_t;

typedef enum {
	SUCCESS,
	FAIL
} res_t;

res_t netbox_login(netbox_state_t* state, char* username, char* password, int peerPort);

res_t netbox_logout(netbox_state_t* state); 

res_t netbox_unregister(netbox_state_t* state);

void print_usage() {
	printf("Usage: ./netbox -m peerport [-n DSIP] [-p DSport]\n");
}

int main(int argc, char** argv) {
	int peer_port = 0;
	char* directory_server_ip = NULL;
	int directory_server_port = 0;

	int argument_index = 1;

	// Read all the options
	while (argument_index < argc) {
		char* option = argv[argument_index];

		if (strcmp(option, "-m") == 0 && argument_index + 1 != argc) {
			peer_port = atoi(argv[argument_index + 1]);

			if (peer_port <= 0) {
				print_usage();
				exit(1);
			}
			argument_index += 2;
		} else if (strcmp(option, "-n") == 0 && argument_index + 1 != argc) {
			directory_server_ip = argv[argument_index + 1];
			argument_index += 2;
		} else if (strcmp(option, "-p") == 0 && argument_index + 1 != argc) {
			directory_server_port = atoi(argv[argument_index + 1]);

			if (directory_server_port <= 0) {
				print_usage();
				exit(1);
			}
			argument_index += 2;
		} else {
			print_usage();
			exit(1);
		}
	}

	// The user needs to specify the Peer Port
	if (peer_port == 0) {
		print_usage();
		exit(1);
	}

	return 0;
}
