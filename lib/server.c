#include "server.h"
#include <string.h>
#include "crypto.h"
#include "base64.h"
#include "keys.h"
#include "network.h"

int sqrl_server_init(sqrl_server_t *server, const char *utf8_url)
{
    sqrl_strbuf_t host = SQRL_STRBUF_INIT;
    sqrl_strbuf_t url_res = SQRL_STRBUF_INIT;
    
    if(!utf8_url) return 1;
    
    sqrl_dict_add(&server->params, kSqrlUrl, utf8_url);
    sqrl_net_get_host(utf8_url, &host);
    sqrl_dict_add(&server->params, kHost, host.str);
    sqrl_net_get_query_params(utf8_url, &server->params);
    sqrl_net_get_url_resource(utf8_url, &url_res);
    sqrl_dict_add(&server->params, kUrlResource, url_res.str);
    
    if(strncmp(utf8_url, kSQRLScheme, 7) == 0)
    {
        server->is_secure = 1;
    }
    else if(strncmp(utf8_url, kQRLScheme, 6) != 0)
    {
        return 1;
    }
    
    return 0;
}

int sqrl_server_add_idk_param(sqrl_server_t *server, sqrl_buffer_t *site_public_key)
{
    sqrl_strbuf_t base64_idk = SQRL_STRBUF_INIT;
    sqrl_base64(&base64_idk, site_public_key->ptr, site_public_key->len);
    sqrl_dict_add(&server->params, kIdk, base64_idk.str);
    sqrl_strbuf_release(&base64_idk);
    return 0;
}

int sqrl_server_set_previous_response(sqrl_server_t *server, sqrl_server_response_t *previous_response)
{
    if(server->previous_response)
    {
        sqrl_server_response_free(server->previous_response);
    }
    server->previous_response = previous_response;
    return 0;
}

void sqrl_server_free(sqrl_server_t *server)
{
    sqrl_dict_free(&server->params);
    sqrl_protected_memory_free(server->site_private_key);
    sqrl_server_set_previous_response(server, 0);
}