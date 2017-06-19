#include "request.h"
#include <stdio.h>
#include <string.h>
#include "keys.h"
#include "network.h"
#include "base64.h"

int sqrl_server_request_add_server_param(sqrl_server_request_t *request, sqrl_server_t *server);

/*
int sqrl_server_request_init(sqrl_server_request_t *request, const char *utf8_url)
{
    int result = 0;
    int is_secure = 0;
    const char *ptr_past_scheme = 0;
    sqrl_strbuf_t http_url = SQRL_STRBUF_INIT;
    sqrl_strbuf_t sqrl_url = SQRL_STRBUF_INIT;
    sqrl_strbuf_t host = SQRL_STRBUF_INIT;
    
    if(!utf8_url) return 0;
    
    sqrl_protected_memory_create(&request->session_private_key, 64);
    sqrl_strbuf_create_from_string(&sqrl_url, utf8_url);
    
    sqrl_dict_add(&request->params, kSqrlUrl, sqrl_url.str);
    
    sqrl_net_get_host(sqrl_dict_get_string(&request->params, kSqrlUrl), &host);
    sqrl_dict_add(&request->params, kHost, host.str);
    
    sqrl_strbuf_create(&http_url, sqrl_url.len + 1);
    
    if(strncmp(sqrl_url.str, "sqrl://", 7) == 0)
    {
        sqrl_strbuf_append_from_cstr(&http_url, "https://");
        is_secure = 1;
    }
    else if(strncmp(sqrl_url.str, "qrl://", 6) == 0)
    {
        sqrl_strbuf_append_from_cstr(&http_url, "http://");
    }
    else
    {
        result = 1;
    }
    if(previous_response)
    {
        sqrl_strbuf_append(&http_url, &host);
        sqrl_strbuf_append_from_cstr(&http_url, sqrl_dict_get_string(&previous_response->sqrl_body, kQry));
    }
    else if(is_secure)
    {
        sqrl_strbuf_append_from_cstr(&http_url, sqrl_url.str + 7);
    }
    else
    {
        sqrl_strbuf_append_from_cstr(&http_url, sqrl_url.str + 6);
    }
    
    if(is_secure) ptr_past_scheme = http_url.str + 8;
    else ptr_past_scheme = http_url.str + 7;
    
    sqrl_dict_add(&request->params, kUrlNoScheme, ptr_past_scheme);
    sqrl_dict_add(&request->params, kHttpUrl, http_url.str);
    sqrl_dict_add(&request->client_params, kVer, kOne);
    
    sqrl_strbuf_release(&http_url);
    sqrl_strbuf_release(&sqrl_url);
    sqrl_strbuf_release(&host);
    
    return result;
}
*/

int sqrl_server_request_init(sqrl_server_request_t *request, sqrl_server_t *server)
{
    int result = 0;
    
    sqrl_strbuf_t http_url = SQRL_STRBUF_INIT;
    //sqrl_strbuf_t sqrl_url = SQRL_STRBUF_INIT;
    //sqrl_strbuf_t host = SQRL_STRBUF_INIT;
    
    //sqrl_strbuf_create_from_string(&sqrl_url, utf8_url);
    //sqrl_dict_add(&request->params, kSqrlUrl, sqrl_url.str);
    
//    sqrl_net_get_host(sqrl_dict_get_string(&request->params, kSqrlUrl), &host);
//    sqrl_dict_add(&request->params, kHost, host.str);
    
    // begin creation of http(s) url
    if(server->is_secure)
    {
        sqrl_strbuf_append_from_cstr(&http_url, kHTTPSScheme);
    }
    else
    {
        sqrl_strbuf_append_from_cstr(&http_url, kHTTPScheme);
    }
    sqrl_strbuf_append_from_cstr(&http_url, sqrl_dict_get_string(&server->params, kHost));
    if(server->previous_response)
    {
        sqrl_strbuf_append_from_cstr(&http_url, sqrl_dict_get_string(&server->previous_response->sqrl_body, kQry));
    }
    else
    {
        sqrl_strbuf_append_from_cstr(&http_url, sqrl_dict_get_string(&server->params, kUrlResource));
        sqrl_strbuf_append_from_cstr(&http_url, "?nut=");
        sqrl_strbuf_append_from_cstr(&http_url, sqrl_dict_get_string(&server->params, kNut));
    }
    
    sqrl_dict_add(&request->params, kHttpUrl, http_url.str);
    sqrl_dict_add(&request->client_params, kVer, kOne);
    
    sqrl_server_request_add_server_param(request, server);
    
    sqrl_dict_add(&request->client_params, kIdk, sqrl_dict_get_string(&server->params, kIdk));
    
    sqrl_strbuf_release(&http_url);
//    sqrl_strbuf_release(&sqrl_url);
//    sqrl_strbuf_release(&host);
    
    return result;
}

//int sqrl_server_request_init_with_previous_response(sqrl_server_request_t *new_request, sqrl_server_t *server)
//{
//    int result = 0;
//    
//    sqrl_strbuf_t http_url = SQRL_STRBUF_INIT;
//    sqrl_strbuf_t sqrl_url = SQRL_STRBUF_INIT;
//    
//    if(!server->previous_response) return 1;
//    
//    if(server->is_secure)
//    {
//        sqrl_strbuf_append_from_cstr(&sqrl_url, kSQRLScheme);
//        sqrl_strbuf_append_from_cstr(&http_url, kHTTPSScheme);
//    }
//    else
//    {
//        sqrl_strbuf_append_from_cstr(&sqrl_url, kQRLScheme);
//        sqrl_strbuf_append_from_cstr(&http_url, kHTTPScheme);
//    }
//    sqrl_strbuf_append_from_cstr(&sqrl_url, sqrl_dict_get_string(&server->previous_response->params, kHost));
//    sqrl_strbuf_append_from_cstr(&http_url, sqrl_dict_get_string(&server->previous_response->params, kHost));
//    sqrl_strbuf_append_from_cstr(&sqrl_url, sqrl_dict_get_string(&server->previous_response->sqrl_body, kQry));
//    sqrl_strbuf_append_from_cstr(&http_url, sqrl_dict_get_string(&server->previous_response->sqrl_body, kQry));
//    
//    return result;
//}

int sqrl_server_request_add_server_param(sqrl_server_request_t *request, sqrl_server_t *server)
{
    sqrl_strbuf_t base64_server = SQRL_STRBUF_INIT;
    
    if(server->previous_response)
    {
        sqrl_dict_add(&request->params, kServer, server->previous_response->sqrl_b64_data.str);
    }
    else
    {
        sqrl_base64(&base64_server, sqrl_dict_get_string(&server->params, kSqrlUrl), strlen(sqrl_dict_get_string(&server->params, kSqrlUrl)));
        sqrl_dict_add(&request->params, kServer, base64_server.str);
        sqrl_strbuf_release(&base64_server);
    }
    return 0;
}

void sqrl_server_request_free(sqrl_server_request_t *request)
{
    sqrl_dict_free(&request->params);
    sqrl_dict_free(&request->client_params);
    sqrl_protected_memory_free(request->session_private_key);
}