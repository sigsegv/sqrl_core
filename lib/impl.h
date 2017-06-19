#ifndef SQRL_IMPL_H
#define SQRL_IMPL_H

#include <stdio.h>
#include "s4.h"
#include "crypto.h"
#include "strbuf.h"
#include "request.h"
#include "response.h"
#include "server.h"

struct sqrl_impl_typ {
    FILE *debug_stm;
    crypto_t *crypto;
    s4_type *identity;
};
typedef struct sqrl_impl_typ sqrl_impl_t;

#define SQRL_CAST(p) ((sqrl_impl_t*)p)

#define SQRL_EOL \r\n

void sqrl_trace(sqrl_impl_t *sqrl, char *fmt, ...);
// only accepts %r with two parameters, uint8_t* and size_t buffer
void sqrl_fprintf(FILE *stm, char *ftm, ...);
// same as above, but only prints if sqrl loggin enabled
void sqrl_trace_buf(sqrl_impl_t *sqrl, char *fmt, ...);


/**
 * Create new identity association with server at url
 */
int sqrl_impl_server_associate(sqrl_impl_t *sqrl, const char *utf_url, const char *utf8_password);

/**
 * Query SQRL server. Logs all resulting info.
 *
 * @param utf8_url the sqrl url to query
 * @param utf8_password the password to use
 *
 * @return zero on success, otherwise error
 */
//int sqrl_impl_server_query(sqrl_impl_t *impl, sqrl_server_request_t *request, sqrl_server_response_t *response);

//int sqrl_impl_server_ident(sqrl_impl_t *impl, sqrl_server_request_t *request, sqrl_server_response_t *response);

#endif