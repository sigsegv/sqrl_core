#include "response.h"
#include "keys.h"

void sqrl_server_response_create(sqrl_server_response_t **response)
{
    *response = calloc(1, sizeof(sqrl_server_response_t));
    sqrl_dict_init(&(*response)->headers);
    sqrl_dict_init(&(*response)->sqrl_body);
    sqrl_strbuf_create(&(*response)->sqrl_b64_data, 256);
    (*response)->http_code = 0;
}

int sqrl_server_response_check_tif_flag(sqrl_server_response_t *response, enum sqrl_tif_flag flag)
{
    char *end = 0;
    const char *tif_str = 0;
    long tif_val = 0;
    tif_str = sqrl_dict_get_string(&response->sqrl_body, kTif);
    if(!tif_str) return 0;
    tif_val = strtol(tif_str, &end, 16);
    return tif_val & flag;
}

void sqrl_server_response_free(sqrl_server_response_t *response)
{
    sqrl_dict_free(&response->headers);
    sqrl_dict_free(&response->sqrl_body);
}