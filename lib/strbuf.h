#ifndef SQRL_STR_BUF_H
#define SQRL_STR_BUF_H

#include <stdlib.h>

// very simple version of GIT strbuf
struct sqrl_strbuf_typ {
    size_t len;
    size_t cap;
    char *str;
};
typedef struct sqrl_strbuf_typ sqrl_strbuf_t;

extern char sqrl_strbuf_buf[];
#define SQRL_STRBUF_INIT { 0, 0, sqrl_strbuf_buf }

/**
 * Null terminated, mutable, string buffer (no encoding implicit)
 */

/**
 * Initialize string buffer.
 *
 * @param cap initial capacity, which can be zero
 */
void sqrl_strbuf_create(sqrl_strbuf_t *strbuf, size_t cap);

/**
 * Create a new string buffer and fill with the string from str
 *
 * @param str the initial string data that the buffer will contain
 */
void sqrl_strbuf_create_from_string(sqrl_strbuf_t *strbuf, const char *str);

/**
 * Assign buffer to this strbuf
 *
 * @param buf the memory to take ownsership of
 * @param len the length of the string
 * @param cap the allocated memory of the buffer
 */
void sqrl_strbuf_attach(sqrl_strbuf_t *strbuf, void *buf, size_t len, size_t cap);

/**
 * Append the string of other to strbuf
 *
 * @param other containing the string to append from
 */
void sqrl_strbuf_append(sqrl_strbuf_t *strbuf, sqrl_strbuf_t *other);

/**
 * Append the string of other to strbuf
 *
 * @param other the string to append from
 */
void sqrl_strbuf_append_from_cstr(sqrl_strbuf_t *strbuf, const char *str);

/**
 * Append the string of other to strbuf
 *
 * @param buf the bytes to append from
 * @param buf_len length of buf
 */
void sqrl_strbuf_append_from_buf(sqrl_strbuf_t *strbuf, const uint8_t *buf, size_t buf_len);

/**
 * Increase buffer to cap
 *
 * @param cap new capacity will be at least cap amount.
 */
void sqrl_strbuf_grow(sqrl_strbuf_t *strbuf, size_t cap);

/**
 * deallocate the string buffer. Do not use again with re-initializing
 */
void sqrl_strbuf_release(sqrl_strbuf_t *strbuf);

/**
 * Take ownsership of the buffer.
 *
 * @param cap the size of the enitre buffer will written to this variable
 */
char* sqrl_strbuf_detach(sqrl_strbuf_t *strbuf, size_t *cap);

#endif // SQRL_STR_BUF_H