#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>

#include "result.h"
#include "netbox.h"


#define MAX_MESSAGE_LENGTH (OP_WORD_LENGTH + 1 + UID_LENGTH + 1 + PASSWORD_LENGTH + 1 + 5 + 1)


static res_t send_udp_message(netbox_state_t *netbox_state, char *message, char *reply, char *expected_op_word, char **status) {
	size_t message_length = strlen(message);

	// send message
	if (send(netbox_state->udp_socket_fd, message, message_length, 0) != (ssize_t)message_length)
		return failure("Couldn't communicate with server.");

	// read reply
	reply[MAX_REPLY_LENGTH] = '\0';  // need to make sure strtok finds an end;
	if (recv(netbox_state->udp_socket_fd, reply, MAX_REPLY_LENGTH, 0) <= 0)
		return failure("Couldn't receive confirmation from the server.");

	char *op_word = strtok(reply, " ");
	*status = strtok(NULL, "\n");

	if (op_word == NULL || strcmp(op_word, expected_op_word))
		return failure("Invalid op word from the server.");
	if (*status == NULL)
		return failure("Invalid status code from the server.");

	return SUCCESS;
}


res_t netbox_setup(netbox_state_t* netbox_state, int peer_server_port, char* directory_server_address, int directory_server_port) {
	netbox_state->directory_server_address = directory_server_address == NULL ? DEFAULT_DIRECTORY_SERVER_ADDRESS : directory_server_address;
	netbox_state->directory_server_port = directory_server_port == 0 ? DEFAULT_DIRECTORY_SERVER_PORT : directory_server_port;
	netbox_state->peer_server_port = peer_server_port;

	// Create the UDP socket and connect it to the Directory Server
	struct addrinfo hints = {0};
	struct addrinfo* server_address_info;

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	char directory_server_port_string[20];
	snprintf(directory_server_port_string, sizeof(directory_server_port_string), "%hu", netbox_state->directory_server_port);

	if (getaddrinfo(netbox_state->directory_server_address, directory_server_port_string, &hints, &server_address_info) != 0)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	int udp_socket_fd = socket(server_address_info->ai_family, server_address_info->ai_socktype, server_address_info->ai_protocol);
	if (udp_socket_fd == -1) {
		freeaddrinfo(server_address_info);
		return failure("Failed to create UDP socket.\n");
	}

	if (connect(udp_socket_fd, server_address_info->ai_addr, server_address_info->ai_addrlen) < 0) {
		freeaddrinfo(server_address_info);
		close(udp_socket_fd);
		return failure("Failed to estabilish UDP connection with the server.\n");
	}

	netbox_state->is_logged_in = false;
	netbox_state->directory_server_address_info = server_address_info;
	netbox_state->udp_socket_fd = udp_socket_fd;

	return SUCCESS;
}


res_t netbox_cleanup(netbox_state_t* netbox_state) {
	if (close(netbox_state->udp_socket_fd) == -1) {
		return failure("Failed to close UDP socket.\n");
	}
	freeaddrinfo(netbox_state->directory_server_address_info);
	return SUCCESS;
}


res_t netbox_login(netbox_state_t* netbox_state, char *uid, char *password) {
	char *p;

	if (uid == NULL || password == NULL)
		return failure("Login usage: login UID password\n");

	// UID
	if (strnlen(uid, UID_LENGTH + 1) != UID_LENGTH)
		return failure("UID must be exactly %d digits.\n", UID_LENGTH);
	p = uid;
	while (*p != '\0')
		if (!isdigit(*p++))
			return failure("UID must only contain digits.\n");

	// password
	if (strnlen(password, PASSWORD_LENGTH + 1) != PASSWORD_LENGTH)
		return failure("Password must be exactly %d characters.\n", PASSWORD_LENGTH);
	p = password;
	while (*p != '\0')
		if (!isalnum(*p++))
			return failure("Password must only contain alphanumeric characters.\n");

	memcpy(netbox_state->uid, uid, UID_LENGTH + 1);
	memcpy(netbox_state->password, password, PASSWORD_LENGTH + 1);

	// build message
	char message[MAX_MESSAGE_LENGTH + 1], reply[MAX_REPLY_LENGTH + 1];  // null char
	sprintf(message, "LIN %s %s %hu\n", netbox_state->uid, netbox_state->password, netbox_state->peer_server_port);

	char *status;
	if (send_udp_message(netbox_state, message, reply, "RLI", &status))
		return FAILURE;

	// see status code
	if (strcmp(status, "OK") == 0)
		printf("Successful login.\n");
	else if (strcmp(status, "NOK") == 0)
		printf("Incorrect login attempt.\n");
	else if (strcmp(status, "REG") == 0)
		printf("New user registered.\n");
	else
		return failure("Unkown status code from the server.");

	// yeih :)
	netbox_state->is_logged_in = true;
	return SUCCESS;
}


res_t netbox_logout(netbox_state_t* netbox_state) {
	// build message
	char message[MAX_MESSAGE_LENGTH + 1], reply[MAX_REPLY_LENGTH + 1];  // null char
	sprintf(message, "LOU %s %s\n", netbox_state->uid, netbox_state->password);

	char *status;
	if (send_udp_message(netbox_state, message, reply, "RLO", &status))
		return FAILURE;

	// see status code
	if (strcmp(status, "OK") == 0)
		printf("Successful logout.\n");
	else if (strcmp(status, "NLG") == 0)
		printf("User not logged in.\n");
	else if (strcmp(status, "UNR") == 0)
		printf("Unknown user.\n");
	else if (strcmp(status, "WRP") == 0)
		printf("Wrong password.\n");
	else
		return failure("Unkown status code from the server.");

	netbox_state->is_logged_in = false;
	return SUCCESS;
}


res_t netbox_unregister(netbox_state_t* netbox_state) {
	// build message
	char message[MAX_MESSAGE_LENGTH + 1], reply[MAX_REPLY_LENGTH + 1];  // null char
	sprintf(message, "LOU %s %s\n", netbox_state->uid, netbox_state->password);

	char *status;
	if (send_udp_message(netbox_state, message, reply, "RUR", &status))
		return FAILURE;

	// see status code
	if (strcmp(status, "OK") == 0)
		printf("Successful unresgiter.\n");
	else if (strcmp(status, "NOK") == 0)
		printf("User not logged in.");
	else if (strcmp(status, "UNR") == 0)
		printf("Unknown user.\n");
	else if (strcmp(status, "WRP") == 0)
		printf("Wrong password.\n");
	else
		return failure("Unknown status code from the server.");

	return SUCCESS;
}
