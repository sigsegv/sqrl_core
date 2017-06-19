#include "strbuf.h"
#include <string.h>

char sqrl_strbuf_buf[1];

void sqrl_strbuf_create(sqrl_strbuf_t *strbuf, size_t cap)
{
    if(cap)
    {
        sqrl_strbuf_grow(strbuf, cap);
    }
    else
    {
        strbuf->cap = strbuf->len = 0;
        strbuf->str = sqrl_strbuf_buf;
    }
}

void sqrl_strbuf_create_from_string(sqrl_strbuf_t *strbuf, const char *str)
{
    const size_t len = strlen(str);
    sqrl_strbuf_grow(strbuf, len + 1);
    memcpy(strbuf->str, str, len);
    strbuf->len = len;
}

void sqrl_strbuf_release(sqrl_strbuf_t *strbuf)
{
    if(strbuf->cap) free(strbuf->str);
}

char* sqrl_strbuf_detach(sqrl_strbuf_t *strbuf, size_t *cap)
{
    *cap = strbuf->cap;
    strbuf->cap = strbuf->len = 0;
    return strbuf->str;
}

void sqrl_strbuf_attach(sqrl_strbuf_t *strbuf, void *buf, size_t len, size_t cap)
{
    sqrl_strbuf_release(strbuf);
    strbuf->str = buf;
    strbuf->len = len;
    strbuf->cap = cap;
}

void sqrl_strbuf_append(sqrl_strbuf_t *strbuf, sqrl_strbuf_t *other)
{
    const size_t req_cap = strbuf->len + other->len + 1;
    if(strbuf->cap < req_cap) sqrl_strbuf_grow(strbuf, req_cap);
    memcpy(strbuf->str + strbuf->len, other->str, other->len);
    strbuf->len = strbuf->len + other->len;
}

void sqrl_strbuf_append_from_cstr(sqrl_strbuf_t *strbuf, const char *str)
{
    sqrl_strbuf_t other = SQRL_STRBUF_INIT;
    sqrl_strbuf_create_from_string(&other, str);
    sqrl_strbuf_append(strbuf, &other);
    sqrl_strbuf_release(&other);
}

void sqrl_strbuf_append_from_buf(sqrl_strbuf_t *strbuf, const uint8_t *buf, size_t buf_len)
{
    sqrl_strbuf_grow(strbuf, strbuf->len + buf_len + 1);
    memcpy(strbuf->str + strbuf->len, buf, buf_len);
    strbuf->len = strbuf->len + buf_len;
}

void sqrl_strbuf_grow(sqrl_strbuf_t *strbuf, size_t cap)
{
    if(strbuf->cap >= cap) return;
    
    char* new_buf = calloc(cap, 1);
    if(!new_buf) return; // TODO GIT calls die() here
    if(strbuf->len) memcpy(new_buf, strbuf->str, strbuf->len);
    if(strbuf->cap) free(strbuf->str);
    strbuf->str = new_buf;
    strbuf->cap = cap;
}