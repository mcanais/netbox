#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>

#include "result.h"
#include "netbox.h"


#define MAX_INPUT_LENGTH (1 << 10)


void print_usage() {
	fprintf(stderr,"Usage: ./netbox -m peerport [-n DSIP] [-p DSport]\n");
}

int main(int argc, char** argv) {
	netbox_state_t netbox_state = {
		.is_logged_in = false,
		.peer_port = -1,
		.directory_server_ip = DSIP,
		.directory_server_port = DSPORT,
	};

	// Read all the options
	int argument_index = 1;
	while (argument_index < argc) {
		char* option = argv[argument_index];

		if (strcmp(option, "-m") == 0 && argument_index + 1 != argc) {
			if (sscanf(argv[argument_index + 1], "%u", &netbox_state.peer_port)) {
				print_usage();
				exit(1);
			}
			argument_index += 2;
		} else if (strcmp(option, "-n") == 0 && argument_index + 1 != argc) {
			netbox_state.directory_server_ip = argv[argument_index + 1];
			argument_index += 2;
		} else if (strcmp(option, "-p") == 0 && argument_index + 1 != argc) {
			if (sscanf(argv[argument_index + 1], "%u", &netbox_state.directory_server_port)) {
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
	if (netbox_state.peer_port == -1) {
		print_usage();
		exit(1);
	}

	netbox_setup(&netbox_state);

	char input_line[MAX_INPUT_LENGTH];
	while (true) {
		if (fgets(input_line, MAX_INPUT_LENGTH, stdin) == NULL) {
			netbox_cleanup(&netbox_state);
			exit(2);
		}

		char *command = strtok(input_line, " ");
		if (command == NULL)
			continue;

		if (strcmp(command, "login") == 0) {
			char *uid = strtok(NULL, " ");
			char *password = strtok(NULL, " ");
			netbox_login(&netbox_state, uid, password);
		}
		else if (strcmp(command, "logout") == 0) {
			netbox_logout(&netbox_state);
		}
		else if (strcmp(command, "unregister") == 0) {
			netbox_unregister(&netbox_state);
		}
		else if (strcmp(command, "exit") == 0) {
			if (!netbox_state.is_logged_in)
				break;
			else
				puts("You are still logged in. Please logout first.");
		}
		else {
			fprintf(stderr, "Invalid command! Do better.\n");
		}
	}

	netbox_cleanup(&netbox_state);

	return 0;
}
