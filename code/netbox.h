#ifndef _NETBOX_H
#define _NETBOX_H

#include <stdbool.h>
#include <netdb.h>

#include "result.h"

#define DEFAULT_DIRECTORY_SERVER_ADDRESS "127.0.0.1"
#define DEFAULT_DIRECTORY_SERVER_PORT 11111

#define UID_LENGTH 6
#define PASSWORD_LENGTH 8
#define OP_WORD_LENGTH 3
#define MAX_REPLY_LENGTH 10


typedef struct netbox_state {
	char uid[UID_LENGTH + 1];
	char password[PASSWORD_LENGTH + 1];
	bool is_logged_in;
	int peer_server_port;
	char* directory_server_address; // Can be either the domain name or an IP string
	int directory_server_port;
	struct addrinfo* directory_server_address_info;
	int udp_socket_fd;
	int tcp_socket_fd;
} netbox_state_t;


res_t netbox_setup(netbox_state_t* netbox_state, int peer_server_port, char* directory_server_address, int directory_server_port);
res_t netbox_cleanup(netbox_state_t* netbox_state);
res_t netbox_login(netbox_state_t* netbox_state, char *uid, char *password);
res_t netbox_logout(netbox_state_t* netbox_state);
res_t netbox_unregister(netbox_state_t* netbox_state);

#endif
