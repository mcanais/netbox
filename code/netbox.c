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
#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <signal.h>

#include "result.h"
#include "netbox.h"

//FIXME: separate this into two files
//FIXME: remove gotos

#define _STRINGFY(x) #x
#define STRINGFY(x) _STRINGFY(x)

#define MAX_UDP_PACKET_LENGTH ((1 << 16) - 20 - 8)  // IP header: 20, UDP header: 8
#define MAX_16B_DIGITS 5
#define MAX_64B_DIGITS 20
#define MAX_RLS_FILENAME_COUNT 50

#define BASE_MESSAGE_LENGTH (OP_WORD_LENGTH + 1 + UID_LENGTH + 1 + PASSWORD_LENGTH + 1)


/**
 * Writes a message to the file.
 * Either all message is written or an error occurs.
 *
 * @param fd              File descriptor that is going to be written to.
 * @param message         Buffer containing the message to write.
 * @param message_length  Size of the message in bytes.
 *
 * @return Whether the operation was successful or not.
 */
static res_t write_all(int fd, char* message, size_t message_length) {
	size_t bytes_written = 0;
	while (bytes_written != message_length) {
		errno = 0;
		ssize_t write_result = write(fd, &(message[bytes_written]), message_length - bytes_written);

		if (write_result == -1) {
			if (errno == EINTR) {
				continue;
			}

			return FAILURE;
		}

		bytes_written += (size_t)write_result;
	}

	return SUCCESS;
}


/**
 * Reads a message from the file until hitting end of file.
 * This message has a fixed maximum length.
 *
 * @param fd                  File descriptor that is going to be read from.
 * @param message             Buffer where the message is going to be read into.
 * @param max_message_length  Maximum message size that can be read in bytes.
 *
 * @return Number of bytes read on success, -1 if it failed.
 */
static ssize_t read_fixed(int fd, char* message, size_t max_message_length) {
	size_t bytes_read = 0;
	while (bytes_read < max_message_length) {
		errno = 0;
		ssize_t read_result = read(fd, &(message[bytes_read]), max_message_length - bytes_read);

		if (read_result == -1) {
			if (errno == EINTR) {
				continue;
			}

			return -1;
		}

		if (read_result == 0) {
			return bytes_read;
		}

		bytes_read += (size_t)read_result;
	}

	return bytes_read;
}


/**
 * Establishes a network connection with the specified server and returns the
 * file descriptor of the socket that was opened.
 *
 * @param tcp_server_address_info  Address info of the server.
 *
 * @return File descriptor of the socket on success, -1 if it failed.
 */
static int establish_network_connection(struct addrinfo* server_address_info) {
	int socket_fd = socket(server_address_info->ai_family, server_address_info->ai_socktype, server_address_info->ai_protocol);

	if (socket_fd == -1) {
		fprintf(stderr, "Failed to create socket.\n");
		return -1;
	}

	if (connect(socket_fd, server_address_info->ai_addr, server_address_info->ai_addrlen) != 0) {
		close(socket_fd);
		fprintf(stderr, "Failed to establish connection.\n");
		return -1;
	}

	// Set socket timeout to 5 seconds
	struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
	if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) != 0) {
		close(socket_fd);
		fprintf(stderr, "Failed to set socket timeout.\n");
		return -1;
	}

	return socket_fd;
}


/**
 * Sends a UDP message to the Directory Server and validates that
 * the response has the expected operation word.
 * Returns the status code of the message sent by the Directory Server.
 *
 * @param netbox_state      Pointer to the netbox state to be initialized.
 * @param message           Buffer containing the message to send to the Directory Server.
 * @param message_length    Size of the message in bytes.
 * @param expected_op_word  Expected operation word of the response sent by the Directory Server.
 * @param[out] status       Pointer to the buffer that will be filled with the status code sent by the Directory Server.
 *
 * @return Whether the operation was successful or not.
 */
static res_t send_udp_message(netbox_state_t *netbox_state, char *message, size_t message_length, char *expected_op_word, char **status) {
	static char reply[MAX_UDP_PACKET_LENGTH + 1];

	if (message_length >= sizeof(reply) || message_length == 0) {
		return failure("Invalid message length.\n");
	}

	// Send the message
	errno = 0;
	ssize_t send_result;
	do {
		send_result = send(netbox_state->directory_server_udp_socket_fd, message, message_length, 0);
	} while (send_result < 0 && errno == EINTR);

	if (send_result < 0) {
		return failure("Failed to send UDP message to Directory Server.\n");
	}

	// Read reply
	ssize_t bytes_read = recv(netbox_state->directory_server_udp_socket_fd, reply, MAX_UDP_PACKET_LENGTH, 0);
	if (bytes_read < 0)
		return failure("Couldn't receive confirmation from the server.\n");

	reply[bytes_read] = '\0';

	if (reply[bytes_read - 1] != '\n') {
		return failure("Invalid response. Must end with newline character.");
	}
 
	char *op_word = strtok(reply, " ");
	*status = strtok(NULL, "\n");

	if (op_word == NULL)
		return failure("Invalid op word from the server.\n");

	if (strcmp(op_word, expected_op_word) != 0) {
		return failure("Invalid op word from the server. Expected: %s, got: %s\n", expected_op_word, op_word);
	}

	if (*status == NULL) {
		return failure("Invalid status code from the server.\n");
	}

	return SUCCESS;
}


/**
 * Receives a TCP message from the specified socket.
 * The message is dynamically allocated on a buffer.
 * The responsibility of freeing the memory used by the buffer is on the caller.
 *
 * @param tcp_socket_fd     File descriptor of the TCP socket
 * @param[out] message      Pointer to the buffer that will be automatically allocated containing the message received.
 * @param max_message_size  Maximum size of the message buffer in bytes.
 *
 * @return Size of the received message in bytes, or -1 if an error occurs.
 */
static ssize_t tcp_receive_message(int tcp_socket_fd, char** message, size_t max_message_size) {
	size_t bytes_received = 0;
	size_t current_buffer_size = 1024;
	char* buffer = malloc(current_buffer_size);

	if (buffer == NULL) {
		failure("Failed to allocate message buffer.\n");
		return -1;
	}

	while (true) {
		ssize_t receive_result = recv(tcp_socket_fd, &(buffer[bytes_received]), current_buffer_size - bytes_received, 0);

		if (receive_result == -1) {
			free(buffer);
			failure("Failed to receive TCP message.\n");
			return -1;
		}

		if (receive_result == 0) {
			// Readjust the message size to only be the used bytes in order to not waste memory
			char* reallocated_buffer = realloc(buffer, bytes_received);

			if (reallocated_buffer == NULL) {
				free(buffer);
				failure("Failed to reallocate message buffer.\n");
				return -1;
			}

			buffer = reallocated_buffer;
			*message = buffer;
			return bytes_received;
		}

		bytes_received += (size_t)receive_result;

		if (bytes_received >= 0.9 * current_buffer_size) {
			if (current_buffer_size * 2 > max_message_size) {
				free(buffer);
				failure("Message buffer exceeded maximum message size.\n");
				return -1;
			}
			current_buffer_size *= 2;
			char* reallocated_buffer = realloc(buffer, current_buffer_size);

			if (reallocated_buffer == NULL) {
				free(buffer);
				failure("Failed to reallocate message buffer.\n");
				return -1;
			}

			buffer = reallocated_buffer;
		}
	}
	
	return -1;
}


static res_t check_uid(char* uid) {
	if (uid == NULL) {
		return failure("UID cannot be NULL.\n");
	}

	if (strnlen(uid, UID_LENGTH + 1) != UID_LENGTH) {
		return failure("UID must be exactly %d digits.\n", UID_LENGTH);
	}

	char* i = uid;
	while (*i != '\0') {
		if (!isdigit(*i++)) {
			return failure("UID must only contain digits.\n");
		}
	}

	return SUCCESS;
}


static res_t check_filename(char *filename) {
	if (filename == NULL) {
		return failure("Filename cannot be NULL\n");
	}

	size_t filename_length = strnlen(filename, MAX_FILENAME_LENGTH + 1);
	if (filename_length == MAX_FILENAME_LENGTH + 1)
		return failure("Filename is too long.\nThe limit is %d characters.\n", MAX_FILENAME_LENGTH);

	unsigned int i;  // filename_length is unsigned
	for (i = 0; i < filename_length; i++) {
		if (filename[i] == '.')
			break;

		if (!isalnum(filename[i]) && filename[i] != '-' && filename[i] != '_')
			return failure(
				"Invalid character in filename base.\n\tfilename %s\n\tchar: '%c'\n"
				"Only letters, digits, - and _ are allowed.\n", filename, filename[i]
			);
	}

	if (i == 0)
		return failure("Filename must have a base name\n");
	else if (i == filename_length)
		return failure("Filename doesn't have extension.\n\tfilename: %s\n", filename);

	if (filename_length - (i + 1) != FILENAME_EXTENSION_SIZE)
		return failure("File must be exactly "STRINGFY(FILENAME_EXTENSION_SIZE)" characters long, like in the good old MS-DOS days.\n\tfilename: %s\n", filename);

	i++;  // i was in the dot char, the extension comes after the dot
	for (; i < filename_length; i++)
		if (!isalnum(filename[i]))
			return failure(
				"Invalid character in file extension.\n\tfilename %s\n\tchar: '%c'\n"
				"Only letters and digits are allowed.\n", filename, filename[i]
			);

	return SUCCESS;
}


static res_t check_file_permissions(char *filename) {
	int ret;

	// existence
	errno = 0;
	ret = access(filename, F_OK);
	if (ret != 0) {
		if (errno != ENOENT)  // it will set the errno to this if the file doesn't exist
			return failure("Couldn't check the file existence.\n\tfile: %s\n", filename);
		else
			return failure("File doesn't exist.\n\tfile: %s\n", filename);
	}

	// permissions
	errno = 0;
	ret = access(filename, R_OK);
	if (ret != 0) {
		if (errno != EACCES)  // it will set the errno to this if the file doesn't have the permission
			return failure("Couldn't check the file permissions.\n\tfile: %s\n", filename);
		else
			return failure("This user doesn't have read permission for the file.\n\tfile: %s\n", filename);
	}

	return SUCCESS;
}


static off_t get_file_size(char *filename) {
	struct stat file_status;
	if (stat(filename, &file_status) < 0) {
		failure("Couldn't get the file size.\n");
		return -1;
	}

	return file_status.st_size;
}


static res_t check_file_size(char *filename) {
	off_t file_size = get_file_size(filename);
	if (file_size == -1)
		return FAILURE;

	if (file_size > MAX_FILE_SIZE)
		return failure("Maximum file size exceeded.\n\tfile: %s\n", filename);

	return SUCCESS;
}


/**
 * Checks whether a file is valid according to the Directory Server requirements.
 *
 * - The file name must have at most 24 characters.
 * - All characters of the name must be either alphanumerical or one these: '-', '_', '.'. 
 * - The file name must have a 3 letter extension (e.g. "dragon.jpg").
 * - The file size must be at most 10 MB.
 * - The file must be readable by the user running the program.
 *
 * @param filename  Name of the file to be checked.
 *
 * @return Success if the file is valid, failure otherwise.
 */
static res_t check_file(char *filename) {
	if (check_filename(filename) != SUCCESS ||
		check_file_permissions(filename) != SUCCESS ||
		check_file_size(filename) != SUCCESS)
		return FAILURE;
	return SUCCESS;
}


res_t netbox_setup(netbox_state_t* netbox_state, int peer_server_port, char* directory_server_address, int directory_server_port) {
	netbox_state->directory_server_address = directory_server_address == NULL ? DEFAULT_DIRECTORY_SERVER_ADDRESS : directory_server_address;
	netbox_state->directory_server_port = directory_server_port == 0 ? DEFAULT_DIRECTORY_SERVER_PORT : directory_server_port;
	netbox_state->peer_server_port = peer_server_port;

	// Ignore SIGPIPE when writing to a socket that was already closed
	// so that we can cleanup properly
	struct sigaction sa = {};
	sa.sa_handler = SIG_IGN;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGPIPE, &sa, NULL);

	// Create the UDP socket and connect it to the Directory Server
	struct addrinfo hints = {};
	struct addrinfo* directory_server_udp_address_info;
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_DGRAM;

	char directory_server_port_string[20];
	snprintf(directory_server_port_string, sizeof(directory_server_port_string), "%hu", netbox_state->directory_server_port);

	if (getaddrinfo(netbox_state->directory_server_address, directory_server_port_string, &hints, &directory_server_udp_address_info) != 0) {
		return failure("Failed to get address info of the Directory Server %s.\n", netbox_state->directory_server_address);
	}

	int udp_socket_fd = establish_network_connection(directory_server_udp_address_info);

	freeaddrinfo(directory_server_udp_address_info);

	if (udp_socket_fd == -1) {
		return failure("Failed to establish UDP connection with the Directory Server %s.\n", netbox_state->directory_server_address);
	}

	struct addrinfo* directory_server_tcp_address_info;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(netbox_state->directory_server_address, directory_server_port_string, &hints, &directory_server_tcp_address_info) != 0) {
		close(udp_socket_fd);
		return failure("Failed to get address info of the Directory Server %s.\n", netbox_state->directory_server_address);
	}

	netbox_state->is_logged_in = false;
	netbox_state->directory_server_udp_socket_fd = udp_socket_fd;
	netbox_state->directory_server_tcp_address_info = directory_server_tcp_address_info;

	return SUCCESS;
}


res_t netbox_cleanup(netbox_state_t* netbox_state) {
	 // No early returning on error, its a best effort approach
	if (netbox_state->is_logged_in) {
		netbox_logout(netbox_state);
	}
	close(netbox_state->directory_server_udp_socket_fd);
	freeaddrinfo(netbox_state->directory_server_tcp_address_info);

	// Restore SIGPIPE default behaviour
	struct sigaction sa = {};
	sa.sa_handler = SIG_DFL;
	sigemptyset(&sa.sa_mask);
	sigaction(SIGPIPE, &sa, NULL);

	return SUCCESS;
}


res_t netbox_login(netbox_state_t* netbox_state, char *uid, char *password) {
	char *p;

	if (netbox_state->is_logged_in)
		return failure("You are already logged in.\n");

	if (uid == NULL || password == NULL)
		return failure("Login usage: login UID password\n");

	if (check_uid(uid) != SUCCESS) {
		return FAILURE;
	}

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
		return failure("Unknown status code from the server.\n");
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
		return failure("Unknown status code from the server.\n");
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


res_t netbox_file_publish(netbox_state_t *netbox_state, char *filename, char *label) {
	if (!netbox_state->is_logged_in) {
		return failure("You are not logged in.\n");
	}

	if (filename == NULL || label == NULL)
		return failure("Publish usage: publish filename label\n");

	if (check_file(filename) != SUCCESS)
		return FAILURE;

	// Can't reuse this easily because the size of file_size is still unknown
	if (strnlen(label, MAX_FILE_LABEL_LENGTH + 1) == MAX_FILE_LABEL_LENGTH + 1)
		return failure("File label is too long.\nThe limit is "STRINGFY(MAX_FILE_LABEL_LENGTH)" characters.\n");

	off_t file_size = get_file_size(filename);
	if (file_size == -1)
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
		return failure("Unknown status code from the server.\n");
	}
	
	return SUCCESS;
}


res_t netbox_file_remove(netbox_state_t *netbox_state, char *filename) {
	if (!netbox_state->is_logged_in) {
		return failure("You are not logged in.\n");
	}

	if (filename == NULL)
		return failure("Remove usage: remove filename\n");

	if (check_filename(filename) != SUCCESS)
		return FAILURE;

	size_t filename_length = strlen(filename);

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
		return failure("Unknown status code from the server.\n");
	}
	
	return SUCCESS;
}


// TODO: documentation
static int parse_filenames(char *filenames, char *filenames_list[], int max_filename_count) {
	if (max_filename_count <= 0) {
		return -1;
	}

	char* first_filename = strtok(filenames, " ");
	if (first_filename == NULL) {
		return 0;
	}
	if (check_filename(first_filename) != SUCCESS) {
		failure("Invalid filename.\n");
		return -1;
	}

	filenames_list[0] = first_filename;
	int i = 1;
	
	while (i < max_filename_count) {
		char* filename = strtok(NULL, " ");

		if (filename == NULL) {
			break;
		}

		if (check_filename(filename) != SUCCESS) {
			failure("Invalid filename.\n");
			return -1;
		}

		filenames_list[i] = filename;
		i += 1;
	}

	return i;
}


res_t netbox_files_list(netbox_state_t *netbox_state) {
	size_t message_length = OP_WORD_LENGTH + 1;
	char message[] = "LST\n";
	
	char *status;
	if (send_udp_message(netbox_state, message, message_length, "RLS", &status))
		return FAILURE;

	status = strtok(status, " ");

	// see status code
	if (strcmp(status, "OK") == 0) {
		// All good
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
		return failure("Unknown status code from the server.\n");
	}

	char *filenames_section = status + strlen(status) + 1;  // skip the status code
	char *filenames_list[MAX_RLS_FILENAME_COUNT] = {};
	int number_of_files = parse_filenames(filenames_section, filenames_list, MAX_RLS_FILENAME_COUNT);

	if (number_of_files == -1) {
		return FAILURE;
	}

	if (number_of_files == 0) {
		printf("No resources to be listed.\n");
	} else {
		printf("Known resources:\n");
	}

	for (int i = 0; i < number_of_files; i += 1) {
		printf("\t%s\n", filenames_list[i]);
	}

	return SUCCESS;
}


int netbox_file_versions(netbox_state_t* netbox_state, char* filename, netbox_file_version_t** file_versions) {
	int tcp_socket_fd = -1;
	char* response_buffer = NULL;
	netbox_file_version_t* versions_buffer = NULL;

	if (check_filename(filename) != SUCCESS) {
		goto fail;
	}

	// =========== Send TCP request and wait for response ===========
	tcp_socket_fd = establish_network_connection(netbox_state->directory_server_tcp_address_info);
	if (tcp_socket_fd == -1) {
		goto fail;
	}

	char request_message[OP_WORD_LENGTH + 1 + MAX_FILENAME_LENGTH + 1 + 1];
	sprintf(request_message, "VRS %s\n", filename);
	size_t request_message_length = strlen(request_message);

	if (write_all(tcp_socket_fd, request_message, request_message_length) != SUCCESS) {
		goto fail;
	}

	ssize_t response_size;
	if ((response_size = tcp_receive_message(tcp_socket_fd, &response_buffer, 1 << 20)) == -1) {
		goto fail;
	}

	char* op_word = strtok(response_buffer, " ");
	if (op_word == NULL || strcmp(op_word, "RVR") != 0) {
		failure("Invalid op word from the server.\n");
		goto fail;
	}

	// =========== Check status code ===========
	char* status = strtok(NULL, " \n");

	if (status == NULL) {
		failure("Invalid status code from the server.\n");
		goto fail;
	}

	if (strcmp(status, "OK") == 0) {
		// All good
	}
	else if (strcmp(status, "NOK") == 0) {
		printf("No peer is available for the specified resource.\n\tfilename: %s\n", filename);
		goto fail;
	}
	else if (strcmp(status, "ERR") == 0) {
		failure("The server received a malformed message and didn't like it.\n");
		goto fail;
	}
	else {
		failure("Unknown status code from the server. %s\n", status);
		goto fail;
	}

	// =========== Read all version entries ===========
	char* start_of_versions = status + strlen(status) + 1;
	int number_of_spaces = 0;

	char* p = start_of_versions;
	while (p < response_buffer + response_size) {
		if (*p == ' ') {
			number_of_spaces += 1;
		}
		p += 1;
	}

	int number_of_versions = (number_of_spaces + 1) / 5;
	versions_buffer = malloc(sizeof(netbox_file_version_t) * number_of_versions);

	if (versions_buffer == NULL) {
		failure("Failed to allocate versions buffer.\n");
		goto fail;
	}

	int total_bytes_read = 0;
	for (int i = 0; i < number_of_versions; i += 1) {
		netbox_file_version_t* file_version = &(versions_buffer[i]);

		int bytes_read = 0;
		char availability[AVAILABILITY_LENGTH + 1];

		int n = sscanf(start_of_versions + total_bytes_read, 
				"%"STRINGFY(UID_LENGTH)"s "
				 "%zu "
				 "%"STRINGFY(MAX_FILE_LABEL_LENGTH)"s "
				 "%"STRINGFY(MAX_PUBLICATION_TIME_LENGTH)"s "
				 "%"STRINGFY(AVAILABILITY_LENGTH)"s%n",
				 file_version->publisher_uid, &(file_version->file_size), file_version->label, file_version->publication_time, availability, &bytes_read);

		if (n == EOF) {
			failure("Failed to read version information.\n");
			goto fail;
		} else if (n < 5) {
			failure("Failed to read version information.\n");
			goto fail;
		}

		if (strcmp(availability, "AVL") == 0) {
			file_version->is_available = true;
		} else if (strcmp(availability, "NAV") == 0) {
			file_version->is_available = false;
		} else {
			failure("Invalid availability status.\n");
			goto fail;
		}

		total_bytes_read += bytes_read;
	}

	*file_versions = versions_buffer;

	free(response_buffer);
	close(tcp_socket_fd);

	return number_of_versions;

fail:
	if (tcp_socket_fd != -1)
		close(tcp_socket_fd);
	if (response_buffer != NULL)
		free(response_buffer);
	if (versions_buffer != NULL)
		free(versions_buffer);

	return -1;
}


res_t netbox_locate_file_from_user(netbox_state_t* netbox_state, char* filename, char* uid, netbox_peer_location_t* peer_location) {
	if (check_filename(filename) != SUCCESS || check_uid(uid) != SUCCESS) {
		return failure("Where usage: where filename UID\n");
	}

	size_t filename_length = strlen(filename);

	size_t message_length = OP_WORD_LENGTH + 1 + filename_length + 1 + UID_LENGTH +  1;
	char message[message_length + 1];  // null char
	sprintf(message, "WHR %s %s\n", filename, uid);
	
	char *response;
	if (send_udp_message(netbox_state, message, message_length, "RWH", &response))
		return FAILURE;

	char status[4];
	memset(status, 0, sizeof(status));
	int bytes_read;
	sscanf(response, "%3s%n", status, &bytes_read);

	if (strcmp(status, "OK") == 0) {
		// All good
	}
	else if (strcmp(status, "NOK") == 0) {
		return failure("The user %s is not actively publishing the file %s.\n", uid, filename);
	}
	else if (strcmp(status, "ERR") == 0) {
		return failure("The server received a malformed message and didn't like it.\n");
	}
	else {
		return failure("Unknown status code from the server.\n");
	}

	if (sscanf(response + bytes_read + 1, "%15s %d", peer_location->address, &(peer_location->port)) != 2) {
		return failure("Could not parse file location properly.\n");
	}

	return SUCCESS;
}


res_t netbox_locate_available_file_version(netbox_state_t* netbox_state, char* filename, netbox_peer_location_t* peer_location) {
	strcpy(peer_location->address, "127.0.0.1");
	peer_location->port = 53435;
	return SUCCESS;

	netbox_file_version_t* file_versions = NULL;
	int number_of_versions = netbox_file_versions(netbox_state, filename, &file_versions);

	if (number_of_versions == -1) {
		return FAILURE;
	}

	netbox_file_version_t* selected_file_version = NULL;

	for (int i = 0; i < number_of_versions; i += 1) {
		netbox_file_version_t* file_version = &(file_versions[i]);

		if (file_version->is_available == true) {
			selected_file_version = file_version;
			break;
		}
	}

	if (selected_file_version == NULL) {
		free(file_versions);
		return failure("There are no available file versions.\n");
	}

	if (netbox_locate_file_from_user(netbox_state, filename, selected_file_version->publisher_uid, peer_location) != SUCCESS) {
		free(file_versions);
		return FAILURE;
	}

	free(file_versions);
	return SUCCESS;
}


/**
 * Establishes a network connection with the specified peer server and returns the
 * file descriptor of the socket that was opened.
 *
 * @param netbox_peer_location_t  Location of the peer server.
 *
 * @return File descriptor of the socket on success, -1 if it failed.
 */
static int establish_peer_network_connection(netbox_peer_location_t* peer_location) {
	struct addrinfo* peer_server_address_info = NULL;
	struct addrinfo hints = {0};
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char peer_server_port_string[6];
	snprintf(peer_server_port_string, sizeof(peer_server_port_string), "%d", peer_location->port);

	if (getaddrinfo(peer_location->address, peer_server_port_string, &hints, &peer_server_address_info) != 0) {
		failure("Failed to get address info for peer %s.\n", peer_location->address);
		return -1;
	}

	int tcp_socket_fd = establish_network_connection(peer_server_address_info);

	if (tcp_socket_fd == -1) {
		freeaddrinfo(peer_server_address_info);
		failure("Failed to establish connection with the peer %s.\n", peer_location->address);
		return -1;
	}

	freeaddrinfo(peer_server_address_info);

	return tcp_socket_fd;
}


static void netbox_file_get_cleanup(int tcp_socket_fd, int output_fd, char* output_file_path) {
	if (output_file_path != NULL) {
		unlink(output_file_path);
	}
	if (tcp_socket_fd != -1) {
		close(tcp_socket_fd);
	}
	if (output_fd != -1) {
		close(output_fd);
	}
}


res_t netbox_file_get(netbox_state_t* netbox_state, char* filename, char* output_file_path) {
	int tcp_socket_fd = -1;
	int output_fd = -1;

	if (check_filename(filename) != SUCCESS) {
		return failure("Get usage: get filename\n");
	}

	// =========== Find the file version to download ===========
	netbox_peer_location_t peer_location;
	if (netbox_locate_available_file_version(netbox_state, filename, &peer_location) != SUCCESS) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return FAILURE;
	}

	// =========== Establish connection with the peer who is serving the file ===========
	if ((tcp_socket_fd = establish_peer_network_connection(&peer_location)) == -1) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return FAILURE;
	}

	// =========== Send GET request  ===========
	char request_message[OP_WORD_LENGTH + 1 + MAX_FILENAME_LENGTH + 1 + 1];
	sprintf(request_message, "GET %s\n", filename);
	size_t request_message_length = strlen(request_message);

	if (write_all(tcp_socket_fd, request_message, request_message_length) != SUCCESS) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return FAILURE;
	}
	
	// =========== Receive response  ===========
	// First we need to read the response header. It is in the following format: RGT status Fsize
	// This header is at most 16 bytes because Fsize is at most 8 bytes and there is a trailing space
	char buffer[1024];
	ssize_t response_result;
	size_t file_size;
	size_t total_file_bytes_read = 0;
	
	// Read header
	memset(buffer, 0, 17);
	if ((response_result = read_fixed(tcp_socket_fd, buffer, 16)) < 0) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return failure("Failed to read GET response header. %d\n", response_result);
	}

	// Check op word
	if (strncmp(buffer, "RGT ", 4) != 0) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return failure("Invalid op word from the peer.\n");
	}

	// Check status code
	if (strncmp(buffer + 4, "OK ", 3) == 0) {
		// All good
	}
	else if (strncmp(buffer + 4, "NOK", 3) == 0) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return failure("The file is not available in this peer.\n\tfilename: %s\n", filename);
	}
	else if (strncmp(buffer + 4, "ERR", 3) == 0) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return failure("The peer received a malformed message and didn't like it.\n");
	}
	else {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return failure("Unknown status code from the peer.\n");
	}

	// Parse file size
	int bytes_consumed;
	if (sscanf(buffer + 7, "%zu%n", &file_size, &bytes_consumed) != 1
	    || bytes_consumed > 8 || file_size > 10000000 || buffer[7 + bytes_consumed] != ' '
	) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return failure("Failed to read file size");
	}

	size_t remaining_header_bytes = (size_t)response_result - (7 + bytes_consumed + 1);
	char* start_of_file_data = buffer + 7 + bytes_consumed + 1;

	// =========== Write file data  ===========
	output_fd = open(output_file_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);

	if (output_fd == -1) {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);
		return failure("Failed to create output file.\n");
	}

	// Write the file data bytes that might have been included with the header response.
	if (remaining_header_bytes > 0) {
		size_t bytes_to_write = file_size < remaining_header_bytes ? file_size : remaining_header_bytes;

		if (write_all(output_fd, start_of_file_data, bytes_to_write) != SUCCESS) {
			netbox_file_get_cleanup(tcp_socket_fd, output_fd, output_file_path);
			return failure("Failed to write to output file.\n");
		}

		total_file_bytes_read += remaining_header_bytes;
	}

	// Read the file data from the network socket, write it to the output file.
	while (total_file_bytes_read < file_size + 1) {
		response_result = read(tcp_socket_fd, buffer, sizeof(buffer));

		if (response_result <= 0) {
			netbox_file_get_cleanup(tcp_socket_fd, output_fd, output_file_path);
			return failure("Failed to read file data.\n");
		}

		size_t bytes_read = (size_t)response_result;

		if (total_file_bytes_read < file_size) {
			size_t bytes_to_write = bytes_read < file_size - total_file_bytes_read ? bytes_read : file_size - total_file_bytes_read;

			if (write_all(output_fd, buffer, bytes_to_write) != SUCCESS) {
				netbox_file_get_cleanup(tcp_socket_fd, output_fd, output_file_path);
				return failure("Failed to write to output file.\n");
			}
		}

		total_file_bytes_read += bytes_read;
	}

	// Check that the last byte received was a newline
	if (buffer[response_result - 1] != '\n') {
		netbox_file_get_cleanup(tcp_socket_fd, output_fd, output_file_path);
		return failure("Invalid response. Must end with newline character.");
	}
	
	printf("Successfully downloaded file %s (%zu bytes) to %s.\n", filename, file_size, output_file_path);

	netbox_file_get_cleanup(tcp_socket_fd, output_fd, NULL);

	return SUCCESS;
}
