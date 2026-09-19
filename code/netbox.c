#include <linux/limits.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/stat.h>
#include <limits.h>

#include "result.h"
#include "netbox.h"


#define BASE_MESSAGE_LENGTH (OP_WORD_LENGTH + 1 + UID_LENGTH + 1 + PASSWORD_LENGTH + 1)
#define MAX_UDP_PACKET_LENGTH ((1 << 16) - 20 - 8)  // IP header: 20, UDP header: 8

#define MAX_16B_DIGITS 5
#define MAX_64B_DIGITS 20

#define MAX_FILE_LABEL_LENGTH (MAX_UDP_PACKET_LENGTH - BASE_MESSAGE_LENGTH - NAME_MAX - 1 - MAX_64B_DIGITS - 2)


const struct timeval udp_timeout = { .tv_sec = 5, .tv_usec = 0 };


static res_t send_udp_message(netbox_state_t *netbox_state, char *message, size_t message_length, char *expected_op_word, char **status) {
	static char reply[MAX_UDP_PACKET_LENGTH + 1];  // null char
	memset(reply, 0, sizeof(reply));  // clear the buffer

	// send message
	if (send(netbox_state->udp_socket_fd, message, message_length, 0) != (ssize_t)message_length)
		return failure("Couldn't communicate with server.\n");

	// read reply
	int bytes_read = recv(netbox_state->udp_socket_fd, reply, MAX_UDP_PACKET_LENGTH, 0);
	if (bytes_read < 0)
		return failure("Couldn't receive confirmation from the server.\n");
 
	char *op_word = strtok(reply, " ");
	*status = strtok(NULL, "\n");

	if (op_word == NULL)
		return failure("Invalid op word from the server.\n");

	if (strcmp(op_word, expected_op_word) != 0) {
		return failure("Invalid op word from the server. Expected: %s, got: %s\n", expected_op_word, op_word);
	}

	if (*status == NULL)
		return failure("Invalid status code from the server.\n");

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

	// Set UDP socket timeout to 5 seconds
	if (setsockopt(udp_socket_fd, SOL_SOCKET, SO_RCVTIMEO, &udp_timeout, sizeof(udp_timeout)) != 0) {
		freeaddrinfo(server_address_info);
		close(udp_socket_fd);
		return failure("Failed to configure UDP socket options.\n");
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

	if (netbox_state->is_logged_in)
		return failure("You are already logged in.\n");

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
	size_t message_length = BASE_MESSAGE_LENGTH + MAX_16B_DIGITS + 1;
	char message[message_length + 1];  // null char
	sprintf(message, "LIN %s %s %hu\n", netbox_state->uid, netbox_state->password, netbox_state->peer_server_port);
	message_length = strlen(message);  // the server port may be less than 5 digits

	char *status;
	if (send_udp_message(netbox_state, message, message_length, "RLI", &status))
		return FAILURE;

	// see status code
	if (strcmp(status, "OK") == 0) {
		printf("Successful login.\n");
	}
	else if (strcmp(status, "REG") == 0) {
		printf("New user registered.\n");
	}
	else if (strcmp(status, "NOK") == 0) {
		return failure("Incorrect login attempt.\n");
	}
	else if (strcmp(status, "ERR") == 0) {
		return failure("The server received a malformed message and didn't like it.\n");
	}
	else {
		return failure("Unkown status code from the server.\n");
	}

	// yeih :)
	netbox_state->is_logged_in = true;
	return SUCCESS;
}


res_t netbox_logout(netbox_state_t* netbox_state) {
	if (!netbox_state->is_logged_in) {
		return failure("You are not logged in.\n");
	}

	// build message
	size_t message_length = BASE_MESSAGE_LENGTH;
	char message[message_length + 1];  // null char
	sprintf(message, "LOU %s %s\n", netbox_state->uid, netbox_state->password);

	char *status;
	if (send_udp_message(netbox_state, message, message_length, "RLO", &status))
		return FAILURE;

	// see status code
	if (strcmp(status, "OK") == 0) {
		printf("Successful logout.\n");
	}
	else if (strcmp(status, "NLG") == 0) {
		netbox_state->is_logged_in = false; // Make sure the client is consistent with the server
		return failure("User not logged in.\n");
	}
	else if (strcmp(status, "UNR") == 0) {
		return failure("Unknown user.\n");
	}
	else if (strcmp(status, "WRP") == 0) {
		return failure("Wrong password.\n");
	}
	else if (strcmp(status, "ERR") == 0) {
		return failure("The server received a malformed message and didn't like it.\n");
	}
	else {
		return failure("Unkown status code from the server.\n");
	}

	netbox_state->is_logged_in = false;
	return SUCCESS;
}


res_t netbox_unregister(netbox_state_t* netbox_state) {
	if (!netbox_state->is_logged_in) {
		return failure("You are not logged in.\n");
	}

	// build message
	size_t message_length = BASE_MESSAGE_LENGTH;
	char message[message_length + 1];  // null char
	sprintf(message, "UNR %s %s\n", netbox_state->uid, netbox_state->password);

	char *status;
	if (send_udp_message(netbox_state, message, message_length, "RUR", &status))
		return FAILURE;

	// see status code
	if (strcmp(status, "OK") == 0) {
		printf("Successfully unregistered user %s.\n", netbox_state->uid);
	}
	else if (strcmp(status, "NOK") == 0) {
		netbox_state->is_logged_in = false; // Make sure the client is consistent with the server
		return failure("User not logged in.\n");
	}
	else if (strcmp(status, "UNR") == 0) {
		return failure("Unknown user.\n");
	}
	else if (strcmp(status, "WRP") == 0) {
		return failure("Wrong password.\n");
	}
	else if (strcmp(status, "ERR") == 0) {
		return failure("The server received a malformed message and didn't like it.\n");
	}
	else {
		return failure("Unknown status code from the server.\n");
	}

	netbox_state->is_logged_in = false;
	return SUCCESS;
}


static bool is_file_valid(char *filename) {
	return !access(filename, R_OK);
}


static off_t get_file_size(char *filename) {
	struct stat file_status;
	if (stat(filename, &file_status) < 0) {
		failure("Couldn't get the file size.\n");
		return -1;
	}

	return file_status.st_size;
}


res_t  netbox_publish(netbox_state_t *netbox_state, char *filename, char *label) {
	if (filename == NULL || label == NULL)
		return failure("Publish usage: publish filename label\n");

	// can't reuse this easly because the size of file_size is still unknown
	if (strnlen(filename, NAME_MAX + 1) == NAME_MAX + 1)
		return failure("Filename is too long.\n");

	if (strnlen(filename, MAX_FILE_LABEL_LENGTH + 1) == MAX_FILE_LABEL_LENGTH + 1)
		return failure("File label is too long.\n");

	if (is_file_valid(filename))
		return FAILURE;

	off_t file_size = get_file_size(filename);
	if (file_size < -1)
		return FAILURE;

	size_t message_length = MAX_UDP_PACKET_LENGTH;
	char message[message_length + 1];  // null char
	sprintf(message, "PUB %s %s %s %ld %s\n", netbox_state->uid, netbox_state->password, filename, file_size, label);
	message_length = strlen(message);
	
	char *status;
	if (send_udp_message(netbox_state, message, message_length, "RPB", &status))
		return FAILURE;

	// see status code
	if (strcmp(status, "OK") == 0) {
		printf("Successful publication.\n");
	}
	else if (strcmp(status, "NOK") == 0) {
		return failure("Unsuccessful publication.\n");
	}
	else if (strcmp(status, "NLG") == 0) {
		netbox_state->is_logged_in = false; // Make sure the client is consistent with the server
		return failure("User not logged in.\n");
	}
	else if (strcmp(status, "UNR") == 0) {
		return failure("Unknown user.\n");
	}
	else if (strcmp(status, "WRP") == 0) {
		return failure("Wrong password.\n");
	}
	else if (strcmp(status, "ERR") == 0) {
		return failure("The server received a malformed message and didn't like it.\n");
	}
	else {
		return failure("Unkown status code from the server.\n");
	}
	
	return SUCCESS;
}


res_t  netbox_remove(netbox_state_t *netbox_state, char *filename) {
	if (filename == NULL)
		return failure("Remove usage: remove filename\n");

	size_t filename_length = strnlen(filename, NAME_MAX + 1);
	if (filename_length == NAME_MAX + 1)
		return failure("Filename is too long.\n");

	size_t message_length = BASE_MESSAGE_LENGTH + filename_length + 1;
	char message[message_length + 1];  // null char
	sprintf(message, "REM %s %s %s\n", netbox_state->uid, netbox_state->password, filename);
	
	char *status;
	if (send_udp_message(netbox_state, message, message_length, "RRM", &status))
		return FAILURE;

	// see status code
	if (strcmp(status, "OK") == 0) {
		printf("Successful removal.\n");
	}
	else if (strcmp(status, "NOK") == 0) {
		return failure("Unsuccessful removal.\n");
	}
	else if (strcmp(status, "NLG") == 0) {
		netbox_state->is_logged_in = false; // Make sure the client is consistent with the server
		return failure("User not logged in.\n");
	}
	else if (strcmp(status, "UNR") == 0) {
		return failure("Unknown user.\n");
	}
	else if (strcmp(status, "WRP") == 0) {
		return failure("Wrong password.\n");
	}
	else if (strcmp(status, "ERR") == 0) {
		return failure("The server received a malformed message and didn't like it.\n");
	}
	else {
		return failure("Unkown status code from the server.\n");
	}
	
	return SUCCESS;
}


res_t  netbox_list(netbox_state_t *netbox_state) {
	size_t message_length = OP_WORD_LENGTH + 1;
	char message[] = "LST\n";
	
	char *status;
	if (send_udp_message(netbox_state, message, message_length, "RLS", &status))
		return FAILURE;

	status = strtok(status, " ");

	// see status code
	if (strcmp(status, "OK") == 0) {
		printf("Known resources:\n");
	}
	else if (strcmp(status, "NOK") == 0) {
		return failure("No resources are currently known.\n");
	}
	else if (strcmp(status, "NLG") == 0) {
		netbox_state->is_logged_in = false; // Make sure the client is consistent with the server
		return failure("User not logged in.\n");
	}
	else if (strcmp(status, "ERR") == 0) {
		return failure("The server received a malformed message and didn't like it.\n");
	}
	else {
		return failure("Unkown status code from the server.\n");
	}

	char *filenames = status + strlen(status) + 1;  // skip the status code
	while (*filenames != '\0')
		if (!isprint(*filenames++))  // letters + digits + special chars + space
			return failure("Invalid response from the server. Invalid filename character.\n");

	char *filename;
	while ((filename = strtok(NULL, " ")) != NULL)
		printf("%s\n", filename);

	return SUCCESS;
}


res_t  netbox_versions(netbox_state_t *netbox_state, char *filename) {
	return SUCCESS;
}
