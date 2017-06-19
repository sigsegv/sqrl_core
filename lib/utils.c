#include "utils.h"
#include <stdlib.h>
#include <string.h>

void print_buffer_as_hex(FILE *stm, const unsigned char *buf, size_t sz)
{
    int i;
    for (i = 0; i < sz; i++)
    {
        fprintf(stm, "%02x", buf[i]);
        if(i > 0 && i % 40 == 0) fprintf(stm, "\n"); // max chars 80, 2 chars per byte
    }
}

void print_buffer_as_dec(FILE *stm, const unsigned char *buf, size_t sz)
{
    int i;
    for (i = 0; i < sz; i++)
    {
        fprintf(stm, "%02x", buf[i]);
        if(i > 0 && i % 40 == 0) fprintf(stm, "\n"); // max chars 80, 2 chars per byte
    }
}

void buffer_to_hex_string(char *sink, const unsigned char *source, size_t sz)
{
    int i;
    for (i = 0; i < sz; i++)
    {
        sprintf(sink + (i*2), "%02x", source[i]);
    }
    sink[sz*2] = 0;
}

void sqrl_buffer_create(sqrl_buffer_t *buf, size_t size)
{
    memset(buf, 0, sizeof(sqrl_buffer_t));
    buf->ptr = calloc(1, size);
    if(buf->ptr) buf->len = size;
}

void sqrl_buffer_grow(sqrl_buffer_t *buf, size_t size)
{
    sqrl_buffer_t temp = SQRL_BUFFER_INIT;
    
    if(buf->len < size)
    {
        if(buf->len > 0)
        {
            temp.ptr = buf->ptr;
            temp.len = buf->len;
        }
        buf->ptr = calloc(1, size);
        if(buf->ptr)
        {
            buf->len = size;
            if(temp.len && temp.ptr)
            {
                memcpy(buf->ptr, temp.ptr, temp.len);
                sqrl_buffer_free(&temp);
            }
        }
    }
}

void sqrl_buffer_free(sqrl_buffer_t *buf)
{
    free(buf->ptr);
}