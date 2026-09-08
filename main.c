typedef struct netbox_state {
	char* username;
	char* password;
	int peerPort;
	// Possivelmente sockets de tcp/udp?
	
} netbox_state_t;

typedef enum {
	SUCCESS,
	FAIL
} res_t;

res_t netbox_login(netbox_state_t* state, char* username, char* password, int peerPort);

res_t netbox_logout(netbox_state_t* state); 

res_t netbox_unregister(netbox_state_t* state);
