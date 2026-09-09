#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/socket.h>

#include "result.h"
#include "netbox.h"

//NOTE: poidiamos trocar o fprintf(stderr, "..."); return FAILURE; por uma função que dá print do erro e devolve FAILURE


#define OP_WORD_LENGTH 3
#define MAX_REPLY_LENGTH 10


res_t netbox_setup(netbox_state_t* state) {
	// please just do connect in the udp socket so that I don't need to use sendto and just use send
	return SUCCESS;
}


res_t netbox_cleanup(netbox_state_t* state) {
	return SUCCESS;
}



res_t netbox_login(netbox_state_t* state, char *uid, char *password) {
	char *p;

	if (uid == NULL || password == NULL) {
		fprintf(stderr, "login usage: login UID password\n");
		return FAILURE;
	}

	// UID
	if (strnlen(uid, UID_LENGTH + 1) != UID_LENGTH) {
		fprintf(stderr, "UID must be exactly %d digits.\n", UID_LENGTH);
		return FAILURE;
	}
	p = uid;
	while (*p != '\0') {
		if (!isdigit(*p++)) {
			fprintf(stderr, "UID must only contain digits.\n");
			return FAILURE;
		}
	}
	memcpy(state->uid, uid, UID_LENGTH + 1);

	// password
	if (strnlen(password, PASSWORD_LENGTH + 1) != PASSWORD_LENGTH) {
		fprintf(stderr, "password must be exactly %d characters.\n", PASSWORD_LENGTH);
		return FAILURE;
	}
	p = password;
	while (*p != '\0') {
		if (!isalnum(*p++)) {
			fprintf(stderr, "password must only contain alphanumeric characters.\n");
			return FAILURE;
		}
	}
	memcpy(state->password, password, PASSWORD_LENGTH + 1);

	// build message
	size_t message_length = OP_WORD_LENGTH + 1 + UID_LENGTH + 1 + PASSWORD_LENGTH + 1;
	char message[message_length + 1];  // null char
	sprintf(message, "LIN %s %s %d\n", state->uid, state->password, state->peer_port);

	// send message
	if (send(state->udp_socket_fd, message, message_length, 0) != message_length) {
		fprintf(stderr, "Couldn't communicate with server.");
		return FAILURE;
	}

	// read reply
	char reply[MAX_REPLY_LENGTH + 1];
	reply[MAX_REPLY_LENGTH] = '\0';  // need to make sure strtok finds an end;
	if(recv(state->udp_socket_fd, reply, MAX_REPLY_LENGTH, 0) <= 0) {
		fprintf(stderr, "Couldn't receive confirmation from the server.");
		return FAILURE;
	}

	char *op_word = strtok(reply, " ");
	char *status = strtok(NULL, "\n");

	if (op_word == NULL || strcmp(op_word, "RLI")) {
		fprintf(stderr, "Invalid op word from the server.");
		return FAILURE;
	}
	if (status == NULL) {
		fprintf(stderr, "Invalid status code from the server.");
		return FAILURE;
	}

	// see status code
	if (strcmp(status, "OK") == 0)
		printf("successful login.");
	else if (strcmp(status, "NOK") == 0)
		printf("incorrect login attempt.");
	else if (strcmp(status, "REG") == 0)
		printf("new user registered.");
	else {
		fprintf(stderr, "Unkown status code from the server.");
		return FAILURE;
	}

	// yeih :)
	state->is_logged_in = true;
	return SUCCESS;
}


res_t netbox_logout(netbox_state_t* state) {
	return SUCCESS;
}


res_t netbox_unregister(netbox_state_t* state) {
	return SUCCESS;
}
