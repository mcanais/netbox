#ifndef _NETBOX_H
#define _NETBOX_H

#include <stdbool.h>

#include "result.h"


#define DSIP "127.0.0.1"
#define DSPORT 11111

#define UID_LENGTH 6
#define PASSWORD_LENGTH 8


typedef struct netbox_state {
	char uid[UID_LENGTH + 1];
	char password[PASSWORD_LENGTH + 1];
	bool is_logged_in;

	int peer_port;
	char* directory_server_ip;
	int directory_server_port;

	int udp_socket_fd;
	int tcp_socket_fd;
} netbox_state_t;


res_t netbox_setup(netbox_state_t* state);
res_t netbox_cleanup(netbox_state_t* state);

res_t netbox_login(netbox_state_t* state, char *uid, char *password);
res_t netbox_logout(netbox_state_t* state);
res_t netbox_unregister(netbox_state_t* state);

#endif
