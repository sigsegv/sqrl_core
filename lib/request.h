#ifndef SQRL_REQUEST_H
#define SQRL_REQUEST_H

#include "strbuf.h"
#include "dict.h"
#include "crypto.h"
#include "response.h"
#include "server.h"

/**
 * Structure for requests to SQRL servers
 */
struct sqrl_server_request_typ {
    sqrl_dict_t params;
    sqrl_dict_t client_params;
    protected_memory_t *session_private_key;
    char is_secure;
};
typedef struct sqrl_server_request_typ sqrl_server_request_t;

#define SQRL_REQUEST_INIT {SQRL_DICT_INIT, SQRL_DICT_INIT}

/**
 * Initialize request structure
 */
int sqrl_server_request_init(sqrl_server_request_t *request, sqrl_server_t *server);

/**
 * Start nth request based on previous request and response
 */
//int sqrl_server_request_init_with_previous_response(sqrl_server_request_t *new_request, sqrl_server_t *server);

/**
 * Add 'server' base64 value to params
 *
 * @param last_response optional
 */
//int sqrl_server_request_add_server_param(sqrl_server_request_t *request, sqrl_server_t *server);

void sqrl_server_request_free(sqrl_server_request_t *request);

#endif
