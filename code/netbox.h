#ifndef _NETBOX_H
#define _NETBOX_H

#include <stdbool.h>
#include <netdb.h>

#include "result.h"

#define DEFAULT_DIRECTORY_SERVER_ADDRESS "193.136.138.142"
#define DEFAULT_DIRECTORY_SERVER_PORT 59000

#define OP_WORD_LENGTH 3
#define UID_LENGTH 6
#define PASSWORD_LENGTH 8


typedef struct netbox_state {
	char uid[UID_LENGTH + 1];
	char password[PASSWORD_LENGTH + 1];
	unsigned short peer_server_port;
	unsigned short directory_server_port;
	char* directory_server_address; // Can be either the domain name or an IP address
	struct addrinfo* directory_server_address_info;
	int udp_socket_fd;
	int tcp_socket_fd;
	bool is_logged_in;
} netbox_state_t;


/**
 * Sets ups the netbox client, which becomes ready to communicate with the Directory Server.
 *
 * @param netbox_state              Pointer to the netbox state to be initialized.
 * @param peer_server_port          Port to which the peer server binds to.
 * @param directory_server_address  IP address or hostname of the Directory Server. If NULL, it is set to the default value.
 * @param directory_server_port     Port on which the Directory Server is accessed. If 0, it is set to the default value.
 *
 * @return Whether the operation was successful or not.
 */
res_t netbox_setup(netbox_state_t* netbox_state, int peer_server_port, char* directory_server_address, int directory_server_port);


/**
 * Cleans up all of the resources used by the netbox client.
 *
 * @param netbox_state  Pointer to the netbox state.
 *
 * @return Whether the operation was successful or not.
 */
res_t netbox_cleanup(netbox_state_t* netbox_state);


/**
 * Attempts to login to the Directory Server.
 * 
 * If the user sent the correct password, the user becomes logged in.
 * Otherwise, the login fails.
 * If its the first time the user is logging in, the user is first registered
 * and then becomes logged in.
 *
 * @param netbox_state  Pointer to the netbox state.
 * @param uid           Username to use in the login
 * @param password      Password to use in the login
 *
 * @return Whether the operation was successful or not.
 */
res_t netbox_login(netbox_state_t* netbox_state, char *uid, char *password);


/**
 * Logs out of the Directory Server.
 * The user must be logged in before logging out.
 * 
 * @param netbox_state  Pointer to the netbox state.
 *
 * @return Whether the operation was successful or not.
 */
res_t netbox_logout(netbox_state_t* netbox_state);


/**
 * Unregisters the user from the Directory Server.
 * The user must be logged in before unregistering.
 * 
 * @param netbox_state  Pointer to the netbox state.
 *
 * @return Whether the operation was successful or not.
 */
res_t netbox_unregister(netbox_state_t* netbox_state);


// TODO: documentation
res_t  netbox_publish_file(netbox_state_t *netbox_state, char *filename, char *label);

res_t  netbox_remove_file(netbox_state_t *netbox_state, char *filename);

res_t  netbox_list(netbox_state_t *netbox_state);

#endif
