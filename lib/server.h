#ifndef SQRL_SERVER_H
#define SQRL_SERVER_H

#include "strbuf.h"
#include "dict.h"
#include "crypto.h"
#include "response.h"

/**
 * Structure for information regarding target SQRL servers
 */
struct sqrl_server_typ {
    sqrl_dict_t params;
    protected_memory_t *site_private_key;
    char is_secure;
    sqrl_server_response_t *previous_response;
};
typedef struct sqrl_server_typ sqrl_server_t;

#define SQRL_SERVER_INIT {SQRL_DICT_INIT, 0, 0, 0}

/**
 * Initialize server structure
 */
int sqrl_server_init(sqrl_server_t *server, const char *utf8_url);

int sqrl_server_set_previous_response(sqrl_server_t *server, sqrl_server_response_t *previous_response);

/**
 * Add base64 'idk' to client_params
 *
 * param site_public_key
 */
int sqrl_server_add_idk_param(sqrl_server_t *server, sqrl_buffer_t *site_public_key);

void sqrl_server_free(sqrl_server_t *server);

#endif