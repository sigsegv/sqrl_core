#ifndef SQRL_RESPONSE_H
#define SQRL_RESPONSE_H

#include "strbuf.h"
#include "dict.h"
#include "tif.h"

/**
 * Structure for responses from SQRL servers
 */
struct sqrl_server_response_typ {
    sqrl_dict_t headers;
    sqrl_dict_t sqrl_body;
    sqrl_strbuf_t sqrl_b64_data;
    uint8_t http_code;
};
typedef struct sqrl_server_response_typ sqrl_server_response_t;
#define SQRL_RESPONSE_INIT { SQRL_DICT_INIT, SQRL_DICT_INIT, SQRL_STRBUF_INIT, 0 }

void sqrl_server_response_create(sqrl_server_response_t **response);

int sqrl_server_response_check_tif_flag(sqrl_server_response_t *response, enum sqrl_tif_flag flag);

void sqrl_server_response_free(sqrl_server_response_t *response);

#endif