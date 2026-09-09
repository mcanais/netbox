#include "result.h"
#include "netbox.h"

res_t netbox_setup(netbox_state_t* state);
res_t netbox_cleanup(netbox_state_t* state);

res_t netbox_login(netbox_state_t* state, char* username, char* password, int peerPort);
res_t netbox_logout(netbox_state_t* state);
res_t netbox_unregister(netbox_state_t* state);
