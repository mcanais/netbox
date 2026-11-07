//TODO: maybe seperate the argument checking in the functions that do that

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/stat.h>

#include "result.h"
#include "netbox.h"

#define MAX_INPUT_LENGTH (1 << 10)


void print_usage() {
	fprintf(stderr, "Usage: ./netbox -m peerport [-n DSIP] [-p DSport]\n");
}


void print_available_commands() {
	printf(
		"List of commands:\n"
		"\tlogin UID password\n"
		"\tlogout\n"
		"\tunregister\n"
		"\tpublish filename label\n"
		"\tremove filename\n"
		"\tlist\n"
		"\tversions filename\n"
		"\tget filename\n"
		"\thelp\n"
		"\texit\n"
	);
}


/*
 * Main loop for user commands.
 */
void user_commands_loop(netbox_state_t* netbox_state) {
	char input_line[MAX_INPUT_LENGTH];
	while (true) {
		printf("\n> ");
		if (fgets(input_line, MAX_INPUT_LENGTH, stdin) == NULL) {
			netbox_cleanup(netbox_state);
			exit(2);
		}

		char *command = strtok(input_line, " \n");
		if (command == NULL)
			continue;

		if (strcmp(command, "login") == 0) {
			char *uid = strtok(NULL, " ");
			char *password = strtok(NULL, " \n");
			netbox_login(netbox_state, uid, password);
		}
		else if (strcmp(command, "logout") == 0) {
			netbox_logout(netbox_state);
		}
		else if (strcmp(command, "unregister") == 0) {
			netbox_unregister(netbox_state);
		}
		else if (strcmp(command, "publish") == 0) {
			char *filename = strtok(NULL, " ");
			char *label = strtok(NULL, " \n");
			netbox_file_publish(netbox_state, filename, label);
		}
		else if (strcmp(command, "remove") == 0) {
			char *filename = strtok(NULL, " \n");
			netbox_file_remove(netbox_state, filename);
		}
		else if (strcmp(command, "list") == 0) {
			netbox_files_list(netbox_state);
		}
		else if (strcmp(command, "versions") == 0) {
			char *filename = strtok(NULL, " \n");
			netbox_file_version_t* file_versions;
			int number_of_versions = netbox_file_versions(netbox_state, filename, &file_versions);

			if (number_of_versions == -1) {
				continue;
			}

			for (int i = 0; i < number_of_versions; i += 1) {
				netbox_file_version_t* file_version = &(file_versions[i]);
				printf("User: %s, File size: %zu, Label: %s, Publication Time: %s, %s\n", file_version->publisher_uid, file_version->file_size, file_version->label, file_version->publication_time, file_version->is_available ? "Available" : "Not available");
			}

			free(file_versions);
		}
		else if (strcmp(command, "get") == 0) {
			char* filename = strtok(NULL, " \n");
			char output_file_path[256];
			mkdir("downloaded_files", 0755);
			snprintf(output_file_path, sizeof(output_file_path), "downloaded_files/%s", filename);
			netbox_file_get(netbox_state, filename, output_file_path);
		}
		else if (strcmp(command, "help") == 0) {
			print_available_commands();
		}
		else if (strcmp(command, "exit") == 0) {
			if (!netbox_state->is_logged_in) {
				break;
			}
			else {
				printf("You are still logged in. Please logout first.\n");
			}
		}
		else {
			fprintf(stderr, "Invalid command! Do better.\n\n");
			print_available_commands();
		}
	}
}


int main(int argc, char** argv) {
	netbox_state_t netbox_state;

	short peer_server_port = -1;
	char* directory_server_address = NULL;
	short directory_server_port = 0;

	// Read all the options
	int argument_index = 1;
	while (argument_index < argc) {
		char* option = argv[argument_index];

		if (strcmp(option, "-m") == 0 && argument_index + 1 != argc) {
			if (sscanf(argv[argument_index + 1], "%hu", &peer_server_port) != 1) {
				print_usage();
				exit(1);
			}
			argument_index += 2;
		} else if (strcmp(option, "-n") == 0 && argument_index + 1 != argc) {
			directory_server_address = argv[argument_index + 1];
			argument_index += 2;
		} else if (strcmp(option, "-p") == 0 && argument_index + 1 != argc) {
			if (sscanf(argv[argument_index + 1], "%hu", &directory_server_port) != 1) {
				print_usage();
				exit(1);
			}
			argument_index += 2;
		} else {
			print_usage();
			exit(1);
		}
	}

	// The user needs to specify the Peer Server Port
	if (peer_server_port == -1) {
		print_usage();
		exit(1);
	}

	if (netbox_setup(&netbox_state, peer_server_port, directory_server_address, directory_server_port) == FAILURE) {
		exit(1);
	}

	printf("Welcome to Netbox!\nSuccessfully connected to server %s on port %d\n", netbox_state.directory_server_address, netbox_state.directory_server_port);

	user_commands_loop(&netbox_state);

	netbox_cleanup(&netbox_state);

	return 0;
}
