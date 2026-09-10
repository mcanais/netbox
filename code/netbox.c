#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdarg.h>

#include "result.h"
#include "netbox.h"

//NOTE: poidiamos trocar o fprintf(stderr, "..."); return FAILURE; por uma função que dá print do erro e devolve FAILURE
//      sure :)

// TODO: fazer documentacao, explicar o contexto do projeto e a big picture
//TODO: dá para criar uma função geral que o netbox_login, logout e unresgister usariam para mandar e receber a resposta

#define MAX_MESSAGE_LENGTH (OP_WORD_LENGTH + 1 + UID_LENGTH + 1 + PASSWORD_LENGTH + 1 + 5 + 1)


inline res_t failure(char *fmt, ...) {
	va_list args;
    va_start(args, fmt);
    fprintf(stderr, fmt, args);
    va_end(args);

	return FAILURE;
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
	snprintf(directory_server_port_string, sizeof(directory_server_port_string), "%d", netbox_state->directory_server_port);

	if (getaddrinfo(netbox_state->directory_server_address, directory_server_port_string, &hints, &server_address_info) != 0)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	int udp_socket_fd = socket(server_address_info->ai_family, server_address_info->ai_socktype, server_address_info->ai_protocol);
	if (udp_socket_fd == -1) {
		freeaddrinfo(server_address_info);
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	}

	if (connect(udp_socket_fd, server_address_info->ai_addr, server_address_info->ai_addrlen) < 0) {
		freeaddrinfo(server_address_info);
		close(udp_socket_fd);
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	}

	netbox_state->is_logged_in = false;
	netbox_state->directory_server_address_info = server_address_info;
	netbox_state->udp_socket_fd = udp_socket_fd;

	return SUCCESS;
}


res_t netbox_cleanup(netbox_state_t* netbox_state) {
	if (close(netbox_state->udp_socket_fd) == -1) {
		//FIXME: error message
		return FAILURE;
	}
	freeaddrinfo(netbox_state->directory_server_address_info);
	return SUCCESS;
}


res_t netbox_login(netbox_state_t* netbox_state, char *uid, char *password) {
	char *p;

	if (uid == NULL || password == NULL)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	// UID
	if (strnlen(uid, UID_LENGTH + 1) != UID_LENGTH)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	p = uid;
	while (*p != '\0')
		if (!isdigit(*p++))
			return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	memcpy(netbox_state->uid, uid, UID_LENGTH + 1);

	// password
	if (strnlen(password, PASSWORD_LENGTH + 1) != PASSWORD_LENGTH)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	p = password;
	while (*p != '\0')
		if (!isalnum(*p++))
			return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	memcpy(netbox_state->password, password, PASSWORD_LENGTH + 1);

	// build message
	char message[MAX_MESSAGE_LENGTH + 1];  // null char
	sprintf(message, "LIN %s %s %d\n", netbox_state->uid, netbox_state->password, netbox_state->peer_server_port);
	size_t message_length = strlen(message);

	// send message
	if (send(netbox_state->udp_socket_fd, message, message_length, 0) != (ssize_t)message_length)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	// read reply
	char reply[MAX_REPLY_LENGTH + 1];
	reply[MAX_REPLY_LENGTH] = '\0';  // need to make sure strtok finds an end;
	if (recv(netbox_state->udp_socket_fd, reply, MAX_REPLY_LENGTH, 0) <= 0)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	char *op_word = strtok(reply, " ");
	char *status = strtok(NULL, "\n");

	if (op_word == NULL || strcmp(op_word, "RLI"))
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	if (status == NULL)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	// see status code
	if (strcmp(status, "OK") == 0)
		printf("successful login.");
	else if (strcmp(status, "NOK") == 0)
		printf("incorrect login attempt.");
	else if (strcmp(status, "REG") == 0)
		printf("new user registered.");
	else
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	// yeih :)
	netbox_state->is_logged_in = true;
	return SUCCESS;
}


res_t netbox_logout(netbox_state_t* netbox_state) {
	// build message
	char message[MAX_MESSAGE_LENGTH + 1];  // null char
	sprintf(message, "LOU %s %s\n", netbox_state->uid, netbox_state->password);
	size_t message_length = strlen(message);

	// send message
	if (send(netbox_state->udp_socket_fd, message, message_length, 0) != (ssize_t)message_length)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	// read reply
	char reply[MAX_REPLY_LENGTH + 1];
	reply[MAX_REPLY_LENGTH] = '\0';  // need to make sure strtok finds an end;
	if (recv(netbox_state->udp_socket_fd, reply, MAX_REPLY_LENGTH, 0) <= 0)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	char *op_word = strtok(reply, " ");
	char *status = strtok(NULL, "\n");

	if (op_word == NULL || strcmp(op_word, "RLO"))
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	if (status == NULL)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	// see status code
	if (strcmp(status, "OK") == 0)
		printf("successful logout.");
	else if (strcmp(status, "NLG") == 0)
		printf("user not logged in.");
	else if (strcmp(status, "UNR") == 0)
		printf("unknown user.");
	else if (strcmp(status, "WRP") == 0)
		printf("wrong password.");
	else
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	return SUCCESS;
}


res_t netbox_unregister(netbox_state_t* netbox_state) {
	// build message
	char message[MAX_MESSAGE_LENGTH + 1];  // null char
	sprintf(message, "LOU %s %s\n", netbox_state->uid, netbox_state->password);
	size_t message_length = strlen(message);

	// send message
	if (send(netbox_state->udp_socket_fd, message, message_length, 0) != (ssize_t)message_length)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	// read reply
	char reply[MAX_REPLY_LENGTH + 1];
	reply[MAX_REPLY_LENGTH] = '\0';  // need to make sure strtok finds an end;
	if (recv(netbox_state->udp_socket_fd, reply, MAX_REPLY_LENGTH, 0) <= 0)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	char *op_word = strtok(reply, " ");
	char *status = strtok(NULL, "\n");

	if (op_word == NULL || strcmp(op_word, "RUR"))
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);
	if (status == NULL)
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	// see status code
	if (strcmp(status, "OK") == 0)
		printf("successful unresgiter.");
	else if (strcmp(status, "NOK") == 0)
		printf("user not logged in.");
	else if (strcmp(status, "UNR") == 0)
		printf("unknown user.");
	else if (strcmp(status, "WRP") == 0)
		printf("wrong password.");
	else
		return failure("Failed to get address info for %s.\n", netbox_state->directory_server_address);

	return SUCCESS;
}
