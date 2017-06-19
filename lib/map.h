#ifndef SQRL_MAP_H
#define SQRL_MAP_H

#include <stdlib.h>
#include "strbuf.h"

/**
 * string based unsorted key-value map fo sqrl data (typically from a server response)
 */
struct sqrl_map_typ {
    sqrl_strbuf_t storage;
};
typedef struct sqrl_map_typ sqrl_map_t;

/**
 * Initialize with data. Call free when done
 */
void sqrl_map_init(sqrl_map_t *map, char* data, size_t data_len);

void sqrl_map_free(sqrl_map_t *map);

/**
 * return non-zero if this contains key
 */
int sqrl_map_contains(sqrl_map_t *map, const char *key);

/**
 * Get value as null terminated string
 */
const char* sqrl_map_as_string(sqrl_map_t *map, const char *key);

/**
 * Get value as int
 */
int sqrl_map_as_int(sqrl_map_t *map, const char *key);

#endif