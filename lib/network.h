#ifndef SQRL_NETWORK_H
#define SQRL_NETWORK_H

#include <string.h>
#include <stdint.h>
#include "strbuf.h"
#include "dict.h"

struct net_client_typ;
typedef struct net_client_typ net_client_t;

///**
// * Initialize Network client.
// *
// * @return zero on success, otherwise error
// */
//int net_create(net_client_t **client);
//
///**
// * Destroy any network resources
// */
//void net_destroy(net_client_t *client);
//
///**
// * Add header for future requests
// */
//int net_add_header(net_client_t *client, const char *utf8_key, const char *utf8_value);
//
//int net_request(net_client_t *client, const char *utf8_method, const char *utf8_url, const char *utf8_body

void net_create(net_client_t **client, const char *utf8_method, const char *utf8_url);

void net_destroy(net_client_t *client);

/**
 * Get 'host' part of url, where 'host' is defined in SQRL spec.
 *
 * @param utf8_url url to parse
 * @param buf host will be written as utf8 string to buf
 * @param buf_sz size of buf
 */
int sqrl_net_get_host(const char *utf8_url, sqrl_strbuf_t *buf);

int sqrl_net_is_secure(const char *utf8_url);

int sqrl_net_get_query_params(const char *utf8_url, sqrl_dict_t *query_out);

int sqrl_net_get_url_resource(const char *utf8_url, sqrl_strbuf_t *url_resource);

/**
 * Create url that contains just the parts the SQRL authenticates.
 */
//int sqrl_net_get_authenticating_domain(const char *utf8_url, sqrl_strbuf_t *buf);

int net_set_header(net_client_t *client, const char *utf8_name, const char *utf8_value);

int net_set_body(net_client_t *client, const void *body, size_t body_len);

int net_execute(net_client_t *client);

uint32_t net_get_status_code(net_client_t *client);

const uint8_t* net_get_body(net_client_t *client);

size_t net_get_body_len(net_client_t *client);

void net_get_headers(net_client_t *client, sqrl_dict_t *headers);


#endif