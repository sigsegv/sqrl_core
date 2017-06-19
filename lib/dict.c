#include "dict.h"
#include <string.h>

void sqrl_dict_init(sqrl_dict_t *dict)
{
    dict->itr = 0;
    sqrl_strbuf_create(&dict->buf, 256);
}

void sqrl_dict_free(sqrl_dict_t *dict)
{
    sqrl_strbuf_release(&dict->buf);
}

void sqrl_dict_add(sqrl_dict_t *dict, const char* key, const char *val)
{
    size_t bytes_required = 0;
    if(!key || !val) return;
    
    bytes_required = strlen(key) + strlen(val) + 2;
    if(dict->buf.cap < dict->buf.len + bytes_required)
    {
        sqrl_strbuf_grow(&dict->buf, dict->buf.cap + bytes_required);
    }
    if(dict->buf.len > 0)
    {
        dict->buf.str[dict->buf.len] = 0;
        dict->buf.len++;
    }
    sqrl_strbuf_append_from_cstr(&dict->buf, key);
    dict->buf.str[dict->buf.len] = 0;
    dict->buf.len++;
    sqrl_strbuf_append_from_cstr(&dict->buf, val);
}

void sqrl_dict_find_key(sqrl_dict_t *dict, const char *key, const char **key_pos, const char **val_pos)
{
    const char *itr0 = 0;
    const char *itr1 = 0;
    size_t key_len = 0;
    size_t val_len = 0;
    size_t rem_bytes = 0;
    
    *key_pos = 0;
    *val_pos = 0;
    itr0 = dict->buf.str;
    if(!itr0) return;
    
    rem_bytes = dict->buf.len;
    while(rem_bytes)
    {
        key_len = strnlen(itr0, rem_bytes);
        rem_bytes -= (key_len < rem_bytes) ? key_len + 1 : rem_bytes;
        if(rem_bytes == 0)
        {
            break;
        }
        itr1 = itr0 + key_len + 1;
        val_len = strnlen(itr1, rem_bytes);
        rem_bytes -= (val_len < rem_bytes) ? val_len + 1 : rem_bytes;
        if(strcmp(itr0, key) == 0)
        {
            *key_pos = itr0;
            *val_pos = itr1;
            rem_bytes = 0;
        }
        else
        {
            itr0 = itr1 + val_len + 1;
        }
    }
}
                       
int sqrl_dict_has(sqrl_dict_t *dict, const char *key)
{
    const char *key_pos, *val_pos;
    
    sqrl_dict_find_key(dict, key, &key_pos, &val_pos);
    
    return (key_pos != 0) ? 1 : 0;
}

const char* sqrl_dict_get_string(sqrl_dict_t *dict, const char* key)
{
    const char *key_pos, *val_pos;
    
    sqrl_dict_find_key(dict, key, &key_pos, &val_pos);
    
    return val_pos;
}

void sqrl_dict_begin(sqrl_dict_t *dict)
{
    dict->itr = dict->buf.str;
}

int sqrl_dict_is_done(sqrl_dict_t *dict)
{
    return dict->itr == 0;
}

void sqrl_dict_next(sqrl_dict_t *dict)
{
    if(!dict || !dict->itr) return;
    
    if(dict->itr >= dict->buf.str + dict->buf.len)
    {
        dict->itr = 0;
    }
    else
    {
        dict->itr += strlen(dict->itr) + 1; // advance to value
        dict->itr += strlen(dict->itr) + 1; // advance to next key
    }
    if(dict->itr >= dict->buf.str + dict->buf.len)
    {
        dict->itr = 0;
    }
}

const char* sqrl_dict_current_key(sqrl_dict_t *dict)
{
    return dict->itr;
}

const char* sqrl_dict_current_value(sqrl_dict_t *dict)
{
    return dict->itr + strlen(dict->itr) + 1;
}