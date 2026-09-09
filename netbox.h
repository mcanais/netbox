#include "result.h"


typedef struct netbox_state {
	char* username;
	char* password;

	bool is_logged_in;

	int peer_port;
	char* directory_server_ip;
	int directory_server_port;

	int udp_socket_fd;
	int tcp_socket_fd;
} netbox_state_t;


#define DSIP "127.0.0.1"
#define DSPORT 11111


res_t netbox_setup(netbox_state_t* state);
res_t netbox_cleanup(netbox_state_t* state);

res_t netbox_login(netbox_state_t* state, char* username, char* password, int peerPort);
res_t netbox_logout(netbox_state_t* state);
res_t netbox_unregister(netbox_state_t* state);

