#ifndef SQRL_DICT_H
#define SQRL_DICT_H

#include "strbuf.h"
#include <stdint.h>

/**
 * Very simple unordered dictionary/map of strings. 
 *
 * Does not support binary data! 
 * No zero bytes allowed!
 */

struct sqrl_dict_typ {
    sqrl_strbuf_t buf;
    char *itr;
};
typedef struct sqrl_dict_typ sqrl_dict_t;

#define SQRL_DICT_INIT { SQRL_STRBUF_INIT, 0 }

void sqrl_dict_init(sqrl_dict_t *dict);

void sqrl_dict_free(sqrl_dict_t *dict);

void sqrl_dict_add(sqrl_dict_t *dict, const char* key, const char *val);

/**
 * @return non-zero if key found
 */
int sqrl_dict_has(sqrl_dict_t *dict, const char *key);

const char* sqrl_dict_get_string(sqrl_dict_t *dict, const char* key);

//void sqrl_dict_get_strbuf(sqrl_dict_t *dict, const char* key, int key_len, sqrl_strbuf_t *buf);

//int sqrl_dict_get_int(sqrl_dict_t *dict, const char* key, int key_len);

/**
 * Begin iterating keys and values
 */
void sqrl_dict_begin(sqrl_dict_t *dict);

/**
 * @return non-zero if done iterating
 */
int sqrl_dict_is_done(sqrl_dict_t *dict);

void sqrl_dict_next(sqrl_dict_t *dict);

const char* sqrl_dict_current_key(sqrl_dict_t *dict);

const char* sqrl_dict_current_value(sqrl_dict_t *dict);

#endif