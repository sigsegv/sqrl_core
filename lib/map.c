#include "map.h"
#include "strbuf.h"

void sqrl_map_init(sqrl_map_t *map, char* data, size_t data_len)
{
    //sqrl_strbuf_create_from_string(map->storage, data);
}

void sqrl_map_free(sqrl_map_t *map)
{
    //sqrl_strbuf_release(map->storage);
}

int sqrl_map_contains(sqrl_map_t *map, const char *key)
{
    return 0;
}

const char* sqrl_map_as_string(sqrl_map_t *map, const char *key)
{
    return 0;
}

int sqrl_map_as_int(sqrl_map_t *map, const char *key)
{
    return 0;
}