#ifndef SQRL_API_H
#define SQRL_API_H

#include <stdio.h>

struct sqrl_typ;
typedef struct sqrl_typ sqrl_t;

/**
 * Initialize SQRL client. Call this before anything else
 *
 * @return zero on success, otherwise error
 */
int sqrl_init(sqrl_t **sqrl);

/**
 * Destroy SQRL client
 */
void sqrl_destroy(sqrl_t *sqrl);

/**
 * Enable debug logging, and write to stm.
 *
 * @param stm the stream to write debugging info to
 */
void sqrl_log(sqrl_t *impl, FILE *stm);

/**
 * Load a SQRL identity.
 *
 * @param stm Typically a file stream to a sqrl or sqrc file
 * @param utf8_password the password of identity to use for authentication
 *
 * @return zero on success, otherwise error
 */
int sqrl_identity_load(sqrl_t *impl, FILE *stm, const char *utf8_password);

/**
 * Load a SQRL identity.
 *
 * @param stm Typically a file stream to which the sqrl
 * identity will be saved to.
 *
 * @return zero on success, otherwise error
 */
int sqrl_identity_save(sqrl_t *impl, FILE *stm);

/**
 * Create a new SQRL identity.
 *
 * @return zero on success, otherwise error
 */
int sqrl_identity_create(sqrl_t *impl);

/**
 * Create new server side identity
 *
 * @param utf8_url null terminated utf8 encoded sqrl server url
 * @param utf8_password null terminated utf8 encoded password
 *
 * @return zero on success, otherwise error
 */
int sqrl_server_associate(sqrl_t *impl, const char *utf8_url, const char *utf8_password);

#endif