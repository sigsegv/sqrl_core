#ifndef UTILS_H
#define UTILS_H

#include <stdio.h>

/**
 * Generic utility functions
 */

void print_buffer_as_hex(FILE *stm, const unsigned char *buf, size_t sz);

/**
 * Convert source into null terminated hex string
 *
 * @param sink must be 2*sz+1 bytes
 * @param source must be sz bytes long
 * @param sz szie of source in bytes
 */
void buffer_to_hex_string(char *sink, const unsigned char *source, size_t sz);

void print_buffer_as_dec(FILE *stm, const unsigned char *buf, size_t sz);

struct sqrl_buffer_typ {
    void *ptr;
    size_t len;
};
typedef struct sqrl_buffer_typ sqrl_buffer_t;
#define SQRL_BUFFER_INIT {0, 0}

/**
 * allocate memory
 */
void sqrl_buffer_create(sqrl_buffer_t *buf, size_t size);

void sqrl_buffer_grow(sqrl_buffer_t *buf, size_t size);

/**
 * free memory
 */
void sqrl_buffer_free(sqrl_buffer_t *buf);

#endif