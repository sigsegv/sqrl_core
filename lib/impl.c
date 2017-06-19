#include "impl.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <stdint.h>
#include "strbuf.h"
#include "network.h"
#include "crypto.h"
#include "base64.h"
#include "keys.h"

const char SQRL_NL[] = "\r\n";

void sqrl_trace(sqrl_impl_t *sqrl, char *fmt, ...)
{
    va_list vlist;
    
    if(sqrl && sqrl->debug_stm)
    {
        va_start(vlist, fmt);
        vfprintf(sqrl->debug_stm, fmt, vlist);
        va_end(vlist);
    }
}

void sqrl_fprintf(FILE *stm, char *fmt, ...)
{
    // implementation based on k&r
    va_list ap;
    char *p;
    uint8_t *buf;
    size_t sz;
    int i;
    
    va_start(ap, fmt);
    for(p = fmt; *p; ++p)
    {
        if(*p != '%')
        {
            fputc(*p, stm);
            continue;
        }
        switch(*++p)
        {
            case 'r':
                buf = va_arg(ap, void*);
                sz = va_arg(ap, size_t);
                for (i = 0; i < sz; i++)
                {
                    fprintf(stm, "%02x", buf[i]);
                }
                break;
        }
    }
    va_end(ap);
}

void sqrl_trace_buf(sqrl_impl_t *sqrl, char *fmt, ...)
{
    // implementation based on k&r
    va_list ap;
    char *p;
    uint8_t *buf;
    size_t sz;
    int i;
    
    if(sqrl && sqrl->debug_stm)
    {
        va_start(ap, fmt);
        for(p = fmt; *p; ++p)
        {
            if(*p != '%')
            {
                fputc(*p, sqrl->debug_stm);
                continue;
            }
            switch(*++p)
            {
                case 'r':
                    buf = va_arg(ap, void*);
                    sz = va_arg(ap, size_t);
                    for (i = 0; i < sz; i++)
                    {
                        fprintf(sqrl->debug_stm, "%02x", buf[i]);
                    }
                    break;
            }
        }
        va_end(ap);
    }
}

void sqrl_impl_log_tif(sqrl_impl_t *sqrl, const char *tif_str)
{
    char *end = 0;
    long tif = 0;
    if(!sqrl->debug_stm) return;
    if(!tif_str) return;
    
    tif = strtol(tif_str, &end, 16);
    sqrl_trace(sqrl, "TIF: ");
    if(tif & e_tif_id_match) sqrl_trace(sqrl, "[ID Match] ");
    if(tif & e_tif_prev_id_match) sqrl_trace(sqrl, "[Prev ID Match] ");
    if(tif & e_tif_ip_match) sqrl_trace(sqrl, "[IP Match] ");
    if(tif & e_tif_sqrl_disabled) sqrl_trace(sqrl, "[SQRL Disabled] ");
    if(tif & e_tif_func_not_supported) sqrl_trace(sqrl, "[Function Not Supported] ");
    if(tif & e_tif_transient_error) sqrl_trace(sqrl, "[Transient Error] ");
    if(tif & e_tif_command_failed) sqrl_trace(sqrl, "[Command Failed] ");
    if(tif & e_tif_client_failure) sqrl_trace(sqrl, "[Client Failure] ");
    if(tif & e_tif_bad_id_association) sqrl_trace(sqrl, "[Bad ID Association] ");
    if(tif & e_tif_invalid_link_origin) sqrl_trace(sqrl, "[Invalid Link Origin] ");
    if(tif & e_tif_suppress_sfn_confirmation) sqrl_trace(sqrl, "[Suppress SFN Confirmation] ");
    sqrl_trace(sqrl, "\n");
}
/*
int sqrl_impl_server_associate2(sqrl_impl_t *sqrl, const char *utf_url, const char *utf8_password)
{
    int result = 0;
    sqrl_server_request_t query_request = SQRL_REQUEST_INIT;
    sqrl_server_response_t query_response = SQRL_RESPONSE_INIT;
    sqrl_server_request_t ident_request = SQRL_REQUEST_INIT;
    sqrl_server_response_t ident_response = SQRL_RESPONSE_INIT;
    
    //sqrl_server_request_init(&query_request, utf_url, utf8_password);
    
    result = sqrl_impl_server_query(sqrl, &query_request, &query_response);
    if(sqrl_dict_has(&query_response.sqrl_body, "tif"))
    {
        sqrl_impl_log_tif(sqrl, sqrl_dict_get_string(&query_response.sqrl_body, "tif"));
    }
    
    
    
    return result;
}*/

int hmac(protected_memory_t *private_key, sqrl_strbuf_t *host, const protected_memory_t *key)
{
    int result = 0;
    result = sqrl_crypto_hmac(private_key->ptr, (uint8_t*)host->str, host->len, key->ptr);
    return result;
}

void parse_response_body(const uint8_t *b64_body, size_t b64_body_len, sqrl_server_response_t *response)
{
    sqrl_buffer_t buf = SQRL_BUFFER_INIT;
    char *token, *value;
    size_t str_len;
    if(b64_body_len == 0) return;
    
    sqrl_strbuf_append_from_buf(&response->sqrl_b64_data, b64_body, b64_body_len);
    sqrl_unbase64(&buf, (const char*)b64_body, b64_body_len);
    
    token = strtok((char*)buf.ptr, "\r\n");
    while(token)
    {
        value = strchr(token, '=');
        if(value)
        {
            str_len = strlen(value);
            if(str_len > 1)
            {
                *value = 0; ++value; // mark '=' as null, and skip
                sqrl_dict_add(&response->sqrl_body, token, value);
            }
            
        }
        token = strtok(0, "\r\n");
    }
    
    sqrl_buffer_free(&buf);
}

int sqrl_impl_server_execute2(sqrl_impl_t *sqrl, sqrl_server_request_t *request, sqrl_server_response_t *response, net_client_t *client)
{
    sqrl_strbuf_t response_body = SQRL_STRBUF_INIT;
    
    net_set_header(client, "User-Agent", "SQRL/1");
    net_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    
    net_execute(client);
    
    response->http_code = net_get_status_code(client);
    sqrl_trace(sqrl, "\n                     <<< SERVER RESPONSE >>>\n");
    sqrl_trace(sqrl, "HTTP Status     : %d\n", response->http_code);
    sqrl_trace(sqrl, "\n                   <<< SERVER RESPONSE DATA >>>\n");
    if(sqrl->debug_stm)
    {
        sqrl_strbuf_append_from_buf(&response_body, net_get_body(client), net_get_body_len(client));
        sqrl_trace(sqrl, "Server Response : %s\n", response_body.str);
    }
    
    sqrl_trace(sqrl, "\n-----------------------HEADERS-----------------------------\n");
    net_get_headers(client, &response->headers);
    for(sqrl_dict_begin(&response->headers); !sqrl_dict_is_done(&response->headers); sqrl_dict_next(&response->headers))
    {
        sqrl_trace(sqrl, "%s=%s\n", sqrl_dict_current_key(&response->headers), sqrl_dict_current_value(&response->headers));
    }
    sqrl_trace(sqrl, "\n-------------------------BODY------------------------------\n");
    parse_response_body(net_get_body(client), net_get_body_len(client), response);
    for(sqrl_dict_begin(&response->sqrl_body); !sqrl_dict_is_done(&response->sqrl_body); sqrl_dict_next(&response->sqrl_body))
    {
        sqrl_trace(sqrl, "%s=%s\n", sqrl_dict_current_key(&response->sqrl_body), sqrl_dict_current_value(&response->sqrl_body));
    }
    sqrl_trace(sqrl, "\n-----------------------------------------------------------\n");
    
    sqrl_strbuf_release(&response_body);
    
    return 0;
}

int sqrl_impl_get_hmac_key(sqrl_impl_t *sqrl, const char *utf8_password, protected_memory_t **hmac_key)
{
    protected_memory_t *password = 0;
    
    sqrl_protected_memory_create(&password, 32);
    sqrl_protected_memory_create(hmac_key, 32);
    
    enscrypt((const uint8_t*)utf8_password, sqrl->identity->scrypt_salt, sizeof(sqrl->identity->scrypt_salt), sqrl->identity->scrypt_n_factor, sqrl->identity->scrypt_iteration_count, password->ptr);
    memcpy((*hmac_key)->ptr, sqrl->identity->enc_identity_master, 32);
    xor_buffer((*hmac_key)->ptr, password->ptr, 32);
    
    sqrl_protected_memory_free(password);
    
    return 0;
}

int sqrl_impl_get_private_key(sqrl_impl_t *sqrl, const char *utf8_url, protected_memory_t *hmac_key, protected_memory_t **private_key)
{
    sqrl_strbuf_t host = SQRL_STRBUF_INIT;
    
    sqrl_protected_memory_create(private_key, 32);
    sqrl_net_get_host(utf8_url, &host);
    hmac(*private_key, &host, hmac_key);
    
    sqrl_trace(sqrl,     "HMAC256 input   : %s\n", host.str);
    sqrl_trace_buf(sqrl, "HMAC256 Hash    : %r\n", (*private_key)->ptr, (*private_key)->len);
    
    return 0;
}

int sqrl_impl_get_site_public_key(sqrl_impl_t *sqrl, protected_memory_t *private_key, sqrl_buffer_t *site_public_key)
{
    sqrl_buffer_grow(site_public_key, 32);
    return make_public_key(site_public_key->ptr, private_key->ptr);
}

int sqrl_impl_get_site_private_key(sqrl_impl_t *sqrl, protected_memory_t *private_key, sqrl_buffer_t *site_public_key, protected_memory_t **site_private_key)
{
    sqrl_protected_memory_create(site_private_key, private_key->len + site_public_key->len);
    memcpy((*site_private_key)->ptr, private_key->ptr, private_key->len);
    memcpy((*site_private_key)->ptr + private_key->len, site_public_key->ptr, site_public_key->len);
    return 0;
}

/**
 * Generate Site/Domain Specific Public Key, and Session Specific Private Key
 *
 * @param request contains original sqrl url
 * @param hmac_key XOR result of master key and enscrypted password
 * @param identity_public_key (IDK) this function fills in with result, client is responsible to free later
 * @param session_private_key this function fills in with result, client is responsible to free later
 * 
 * @return zero on success
 *
int sqrl_impl_gen_site_keys(sqrl_impl_t *sqrl, sqrl_server_request_t *request, protected_memory_t *hmac_key, sqrl_buffer_t *identity_public_key, protected_memory_t **session_private_key)
{
    sqrl_strbuf_t host = SQRL_STRBUF_INIT;
    protected_memory_t *private_key = 0;
    
    // Generate Private Key
    sqrl_protected_memory_create(&private_key, 32);
    sqrl_net_get_host(sqrl_dict_get_string(&request->params, kSqrlUrl), &host);
    sqrl_dict_add(&request->params, kHost, host.str);
    hmac(private_key, &host, hmac_key);
    
    // Generate Identity Public Key(aka IDK)
    sqrl_buffer_create(identity_public_key, 32);
    make_public_key(identity_public_key->ptr, private_key->ptr);
    
    // Generate Identity Authentication (used later to generate IDS)
    sqrl_protected_memory_create(session_private_key, private_key->len + identity_public_key->len);
    memcpy((*session_private_key)->ptr, private_key->ptr, private_key->len);
    memcpy((*session_private_key)->ptr + private_key->len, identity_public_key->ptr, identity_public_key->len);
    
    sqrl_trace(sqrl,     "HMAC256 input   : %s\n", host.str);
    sqrl_trace_buf(sqrl, "HMAC256 Hash    : %r\n", private_key->ptr, private_key->len);
    sqrl_trace_buf(sqrl, "Site Private Key: %r\n", (*session_private_key)->ptr, (*session_private_key)->len);
    sqrl_trace_buf(sqrl, "Site Public Key : %r\n", identity_public_key->ptr, identity_public_key->len);
    
    sqrl_protected_memory_free(private_key);
    sqrl_strbuf_release(&host);
    return 0;
}

int sqrl_impl_server_request_init(sqrl_impl_t *sqrl, const char *utf8_url, sqrl_server_request_t *request)
{
    
    protected_memory_t *hmac_key = 0;
    sqrl_buffer_t identity_public_key = SQRL_BUFFER_INIT;
    protected_memory_t *session_private_key = 0;
    
    sqrl_impl_get_site_private_key(request, utf8_url, utf8_password, priv);
    
    sqrl_trace(sqrl, "~~~~~~~~~~~~~~~~~~~ Beginning SQRL Transaction ~~~~~~~~~~~~~~~~~~~\n");
    sqrl_trace(sqrl, "               <<< CLIENT POST QUERY GENERATION >>>\n");
    sqrl_trace(sqrl, "SQRL URL        : %s\n", sqrl_dict_get_string(&request->params, kSqrlUrl));
    sqrl_trace(sqrl, "Hostname        : %s\n", sqrl_dict_get_string(&request->params, kHost));
    //sqrl_trace(sqrl, "Domain String   : %s\n", request->utf8_input_url.str);
    //sqrl_trace(sqrl, "Secure Query    : %s\n", request->utf8_input_url.str);
    //sqrl_trace(sqrl, "Query Port      : %s\n", request->utf8_input_url.str);
    //sqrl_trace(sqrl, "URL Resource    : %s\n", request->utf8_input_url.str);
    //sqrl_trace(sqrl, "ID Master Key   : %s\n", request->utf8_input_url.str);
    
    sqrl_impl_gen_hmac_key(sqrl,utf8_password, &hmac_key);
    sqrl_impl_gen_site_keys(sqrl, request, hmac_key, &identity_public_key, &request->session_private_key);
    sqrl_protected_memory_free(hmac_key);
    
    
    
    return 0;
}
 */
int sqrl_impl_server_gen_b64client(sqrl_server_request_t *request, sqrl_strbuf_t *buf)
{
    sqrl_strbuf_t temp = SQRL_STRBUF_INIT;
    // iterate request client_params... don't forget '=' and EOL
    for(sqrl_dict_begin(&request->client_params); !sqrl_dict_is_done(&request->client_params); sqrl_dict_next(&request->client_params))
    {
        sqrl_strbuf_append_from_cstr(&temp, sqrl_dict_current_key(&request->client_params));
        sqrl_strbuf_append_from_cstr(&temp, "=");
        sqrl_strbuf_append_from_cstr(&temp, sqrl_dict_current_value(&request->client_params));
        sqrl_strbuf_append_from_cstr(&temp, SQRL_NL);
    }
    sqrl_base64(buf, temp.str, temp.len);
    return 0;
}

int sqrl_impl_server_execute(sqrl_impl_t *sqrl, sqrl_server_request_t *request, sqrl_server_t *server);

int sqrl_impl_server_query(sqrl_impl_t *sqrl, sqrl_server_t *server)
{
    sqrl_server_request_t request = SQRL_REQUEST_INIT;
    
    sqrl_server_request_init(&request, server);
    sqrl_dict_add(&request.client_params, kCmd, kCmdQuery);
    //sqrl_server_request_add_idk_param(&request, site_public_key);
    
    sqrl_impl_server_execute(sqrl, &request, server);
    
    sqrl_server_request_free(&request);
    
    return 0;
}

int sqrl_impl_server_ident(sqrl_impl_t *sqrl, sqrl_server_t *server)
{
    // QUESTION Difference between the following?
    // crypto_sign_seed_keypair
    // crypto_sign_ed25519_seed_keypair
    // crypto_scalarmult_base
    
    sqrl_server_request_t request = SQRL_REQUEST_INIT;
    protected_memory_t *random_lock = 0;
    protected_memory_t *dhka_shared_secret = 0;
    sqrl_buffer_t server_unlock = SQRL_BUFFER_INIT;
    sqrl_buffer_t verify_unlock = SQRL_BUFFER_INIT;
    sqrl_strbuf_t base64_suk = SQRL_STRBUF_INIT;
    sqrl_strbuf_t base64_vuk = SQRL_STRBUF_INIT;
    
    if(!server->previous_response) return 1;
    
    // TODO need to update URL with 'qry' parameter
    
    sqrl_server_request_init(&request, server);
    sqrl_dict_add(&request.client_params, kCmd, kCmdIdent);
    
    if(sqrl_server_response_check_tif_flag(server->previous_response, e_tif_id_match) == 0)
    {
        // creating new id
        sqrl_protected_memory_create(&random_lock, 32);
        memset_random(random_lock->ptr, 32);
        sqrl_buffer_create(&server_unlock, 32);
        make_public_key(server_unlock.ptr, random_lock->ptr);
        
        sqrl_protected_memory_create(&dhka_shared_secret, 32);
        sqrl_crypto_dhka(dhka_shared_secret->ptr, sqrl->identity->enc_identity_lock, random_lock->ptr);
        sqrl_protected_memory_free(random_lock);
        
        sqrl_buffer_create(&verify_unlock, 32);
        sign_public(verify_unlock.ptr, dhka_shared_secret->ptr);
        
        sqrl_base64(&base64_suk, server_unlock.ptr, server_unlock.len);
        sqrl_base64(&base64_vuk, verify_unlock.ptr, verify_unlock.len);
        
        sqrl_dict_add(&request.client_params, kVuk, base64_vuk.str);
        sqrl_dict_add(&request.client_params, kSuk, base64_suk.str);
    }
    
    sqrl_impl_server_execute(sqrl, &request, server);
    
    sqrl_buffer_free(&verify_unlock);
    sqrl_buffer_free(&server_unlock);
    sqrl_server_request_free(&request);
    
    return 0;
}

int sqrl_impl_server_associate(sqrl_impl_t *sqrl, const char *utf8_url, const char *utf8_password)
{
    int result = 0;
    protected_memory_t *hmac_key = 0;
    protected_memory_t *private_key = 0;
    protected_memory_t *site_private_key = 0;
    sqrl_buffer_t site_public_key = SQRL_BUFFER_INIT;
    sqrl_server_response_t response_query = SQRL_RESPONSE_INIT;
    sqrl_server_response_t response_ident = SQRL_RESPONSE_INIT;
    sqrl_server_t server = SQRL_SERVER_INIT;
    
    sqrl_impl_get_hmac_key(sqrl, utf8_password, &hmac_key);
    sqrl_impl_get_private_key(sqrl, utf8_url, hmac_key, &private_key);
    sqrl_protected_memory_free(hmac_key);
    
    sqrl_impl_get_site_public_key(sqrl, private_key, &site_public_key); // IDK
    sqrl_impl_get_site_private_key(sqrl, private_key, &site_public_key, &site_private_key);
    sqrl_protected_memory_free(private_key);
    sqrl_trace_buf(sqrl, "Site Private Key: %r\n", site_private_key->ptr, site_private_key->len);
    sqrl_trace_buf(sqrl, "Site Public Key : %r\n", site_public_key.ptr, site_public_key.len);
    
    sqrl_server_init(&server, utf8_url);
    server.site_private_key = site_private_key;
    sqrl_server_add_idk_param(&server, &site_public_key);
    
    sqrl_impl_server_query(sqrl, &server);
    sqrl_impl_server_ident(sqrl, &server);
    sqrl_server_free(&server);
    
    sqrl_buffer_free(&site_public_key);
    sqrl_server_response_free(&response_query);
    sqrl_server_response_free(&response_ident);
    
    return result;
}

//int sqrl_impl_server_associate(sqrl_impl_t *sqrl, const char *utf8_url, const char *utf8_password)
//{
//    // Good Works!!!
//    int result = 0;
//    protected_memory_t *private_key = 0;
//    protected_memory_t *site_private_key = 0;
//    sqrl_buffer_t site_public_key = SQRL_BUFFER_INIT;
//    sqrl_server_request_t request = SQRL_REQUEST_INIT;
//    sqrl_server_response_t response = SQRL_RESPONSE_INIT;
//    
//    sqrl_impl_get_private_key(sqrl, utf8_url, utf8_password, &private_key);
//    sqrl_impl_get_site_public_key(sqrl, private_key, &site_public_key); // IDK
//    sqrl_impl_get_site_private_key(sqrl, private_key, &site_public_key, &site_private_key);
//    sqrl_protected_memory_free(private_key);
//    sqrl_trace_buf(sqrl, "Site Private Key: %r\n", site_private_key->ptr, site_private_key->len);
//    sqrl_trace_buf(sqrl, "Site Public Key : %r\n", site_public_key.ptr, site_public_key.len);
//    sqrl_server_request_init(&request, utf8_url);
//    sqrl_server_request_add_server_param(&request, 0);
//    sqrl_dict_add(&request.client_params, kCmd, kQry);
//    sqrl_server_request_add_idk_param(&request, &site_public_key);
//    
//    sqrl_impl_server_execute(sqrl, &request, &response, site_private_key);
//    
//    sqrl_buffer_free(&site_public_key);
//    sqrl_server_request_free(&request);
//    sqrl_server_response_free(&response);
//    
//    return result;
//}

int sqrl_impl_server_execute(sqrl_impl_t *sqrl, sqrl_server_request_t *request, sqrl_server_t *server)
{
    net_client_t *client = 0;
    sqrl_server_response_t *response = 0;
    sqrl_strbuf_t response_body = SQRL_STRBUF_INIT;
    sqrl_strbuf_t base64_client = SQRL_STRBUF_INIT;
    sqrl_strbuf_t base64_ids = SQRL_STRBUF_INIT;
    sqrl_strbuf_t buf_to_sign = SQRL_STRBUF_INIT;
    sqrl_strbuf_t request_body = SQRL_STRBUF_INIT;
    sqrl_buffer_t ids = SQRL_BUFFER_INIT;
    
    sqrl_trace(sqrl, "Request Parameters\n");
    for(sqrl_dict_begin(&request->params); !sqrl_dict_is_done(&request->params); sqrl_dict_next(&request->params))
    {
        sqrl_trace(sqrl, "\t%s:%s\n", sqrl_dict_current_key(&request->params), sqrl_dict_current_value(&request->params));
    }
    sqrl_trace(sqrl, "Request Client Parameters\n");
    for(sqrl_dict_begin(&request->client_params); !sqrl_dict_is_done(&request->client_params); sqrl_dict_next(&request->client_params))
    {
        sqrl_trace(sqrl, "\t%s:%s\n", sqrl_dict_current_key(&request->client_params), sqrl_dict_current_value(&request->client_params));
    }
    
    sqrl_impl_server_gen_b64client(request, &base64_client);
    
    sqrl_strbuf_create_from_string(&buf_to_sign, base64_client.str);
    sqrl_strbuf_append_from_cstr(&buf_to_sign, sqrl_dict_get_string(&request->params, kServer));
    
    sqrl_buffer_create(&ids, 64);
    crypto_signature(ids.ptr, ids.len, (const uint8_t*)buf_to_sign.str, buf_to_sign.len, server->site_private_key->ptr, server->site_private_key->len);
    sqrl_base64(&base64_ids, ids.ptr, ids.len);
    
    /* end crypto calculations */
    
    sqrl_strbuf_create_from_string(&request_body, "client=");
    sqrl_strbuf_append(&request_body, &base64_client);
    sqrl_strbuf_append_from_cstr(&request_body, "&server=");
    sqrl_strbuf_append_from_cstr(&request_body, sqrl_dict_get_string(&request->params, kServer));
    sqrl_strbuf_append_from_cstr(&request_body, "&ids=");
    sqrl_strbuf_append(&request_body, &base64_ids);
    
    sqrl_trace(sqrl, "~~~~~~~~~~~~~~~~~~~ Beginning SQRL Transaction ~~~~~~~~~~~~~~~~~~~\n");
    sqrl_trace(sqrl, "               <<< CLIENT POST QUERY GENERATION >>>\n");
    sqrl_trace(sqrl, "SQRL URL        : %s\n", sqrl_dict_get_string(&request->params, kSqrlUrl));
    sqrl_trace(sqrl, "Hostname        : %s\n", sqrl_dict_get_string(&request->params, kHost));
    
    sqrl_trace(sqrl, "Command Verb    : query\n");
    sqrl_trace(sqrl, "----------------+ Client's parameter list +----------------\n");
    for(sqrl_dict_begin(&request->client_params); !sqrl_dict_is_done(&request->client_params); sqrl_dict_next(&request->client_params))
    {
        sqrl_trace(sqrl, "%s=%s\n", sqrl_dict_current_key(&request->client_params), sqrl_dict_current_value(&request->client_params));
    }
    sqrl_trace(sqrl, "\n-----------------------------------------------------------\n");
    sqrl_trace(sqrl, "'client=' value : %s\n", base64_client.str);
    sqrl_trace(sqrl, "'server=' value : %s\n", sqrl_dict_get_string(&request->params, kServer));
    sqrl_trace(sqrl, "Buffer to sign  : %s\n", buf_to_sign.str);
    sqrl_trace(sqrl, "IDS (base64url) : %s\n", base64_ids.str);
    sqrl_trace(sqrl, "POST Data String: %s\n", request_body.str);
    
    net_create(&client, "post", sqrl_dict_get_string(&request->params, kHttpUrl));
    
    net_set_body(client, request_body.str, request_body.len);
    
    net_set_header(client, "User-Agent", "SQRL/1");
    net_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
    
    net_execute(client);
    
    sqrl_server_response_create(&response);
    sqrl_server_set_previous_response(server, response);
    
    response->http_code = net_get_status_code(client);
    sqrl_trace(sqrl, "\n                     <<< SERVER RESPONSE >>>\n");
    sqrl_trace(sqrl, "HTTP Status     : %d\n", response->http_code);
    sqrl_trace(sqrl, "\n                   <<< SERVER RESPONSE DATA >>>\n");
    if(sqrl->debug_stm)
    {
        sqrl_strbuf_append_from_buf(&response_body, net_get_body(client), net_get_body_len(client));
        sqrl_trace(sqrl, "Server Response : %s\n", response_body.str);
    }
    
    sqrl_trace(sqrl, "\n-----------------------HEADERS-----------------------------\n");
    net_get_headers(client, &response->headers);
    for(sqrl_dict_begin(&response->headers); !sqrl_dict_is_done(&response->headers); sqrl_dict_next(&response->headers))
    {
        sqrl_trace(sqrl, "%s=%s\n", sqrl_dict_current_key(&response->headers), sqrl_dict_current_value(&response->headers));
    }
    sqrl_trace(sqrl, "\n-------------------------BODY------------------------------\n");
    parse_response_body(net_get_body(client), net_get_body_len(client), response);
    for(sqrl_dict_begin(&response->sqrl_body); !sqrl_dict_is_done(&response->sqrl_body); sqrl_dict_next(&response->sqrl_body))
    {
        sqrl_trace(sqrl, "%s=%s\n", sqrl_dict_current_key(&response->sqrl_body), sqrl_dict_current_value(&response->sqrl_body));
    }
    sqrl_trace(sqrl, "\n-----------------------------------------------------------\n");
    
    sqrl_impl_log_tif(sqrl, sqrl_dict_get_string(&response->sqrl_body, kTif));
    
    sqrl_strbuf_release(&response_body);
    sqrl_strbuf_release(&base64_client);
    sqrl_strbuf_release(&buf_to_sign);
    sqrl_strbuf_release(&base64_ids);
    sqrl_strbuf_release(&request_body);
    sqrl_buffer_free(&ids);
    
    return 0;
}

int sqrl_impl_server_query2(sqrl_impl_t *sqrl, sqrl_server_request_t *request, sqrl_server_response_t *response)
{
    int result = 0;
    net_client_t *client = 0;
    protected_memory_t *password = 0;
    protected_memory_t *identity_master = 0;
    protected_memory_t *private_key = 0;
    protected_memory_t *site_private_key = 0;
    sqrl_buffer_t identity_public_key = SQRL_BUFFER_INIT;
    sqrl_buffer_t ids = SQRL_BUFFER_INIT;
    sqrl_strbuf_t host = SQRL_STRBUF_INIT;
    sqrl_strbuf_t body = SQRL_STRBUF_INIT;
    sqrl_strbuf_t base64_idk = SQRL_STRBUF_INIT;
    sqrl_strbuf_t base64_client = SQRL_STRBUF_INIT;
    sqrl_strbuf_t base64_server = SQRL_STRBUF_INIT;
    sqrl_strbuf_t buf_to_sign = SQRL_STRBUF_INIT;
    sqrl_strbuf_t base64_ids = SQRL_STRBUF_INIT;
    sqrl_strbuf_t request_body = SQRL_STRBUF_INIT;
    
    
    if(!sqrl_dict_has(&request->params, kSqrlUrl)) return 1;
    if(!sqrl_dict_has(&request->params, kHttpUrl)) return 1;
    //if(!sqrl_dict_has(&request->params, kUrlNoScheme)) return 1;
    
    sqrl_trace(sqrl, "~~~~~~~~~~~~~~~~~~~ Beginning SQRL Transaction ~~~~~~~~~~~~~~~~~~~\n");
    sqrl_trace(sqrl, "               <<< CLIENT POST QUERY GENERATION >>>\n");
    sqrl_trace(sqrl, "SQRL URL        : %s\n", sqrl_dict_get_string(&request->params, kSqrlUrl));
    
    sqrl_protected_memory_create(&password, 32);
    sqrl_protected_memory_create(&identity_master, 32);
    sqrl_protected_memory_create(&private_key, 32);
    
    /* begin crypto calculations */
    sqrl_net_get_host(sqrl_dict_get_string(&request->params, kSqrlUrl), &host);
    sqrl_trace(sqrl, "Hostname        : %s\n", host.str);
    //sqrl_trace(sqrl, "Domain String   : %s\n", request->utf8_input_url.str);
    //sqrl_trace(sqrl, "Secure Query    : %s\n", request->utf8_input_url.str);
    //sqrl_trace(sqrl, "Query Port      : %s\n", request->utf8_input_url.str);
    //sqrl_trace(sqrl, "URL Resource    : %s\n", request->utf8_input_url.str);
    //sqrl_trace(sqrl, "ID Master Key   : %s\n", request->utf8_input_url.str);
    
    enscrypt((const uint8_t*)sqrl_dict_get_string(&request->params, kPassword), sqrl->identity->scrypt_salt, sizeof(sqrl->identity->scrypt_salt), sqrl->identity->scrypt_n_factor, sqrl->identity->scrypt_iteration_count, password->ptr);
    memcpy(identity_master->ptr, sqrl->identity->enc_identity_master, 32);
    xor_buffer(identity_master->ptr, password->ptr, 32);
    sqrl_protected_memory_free(password);
    
    hmac(private_key, &host, identity_master);
    sqrl_protected_memory_free(identity_master);
    sqrl_trace(sqrl,     "HMAC256 input   : %s\n", host.str);
    sqrl_trace_buf(sqrl, "HMAC256 Hash    : %r\n", private_key->ptr, private_key->len);
    
    sqrl_buffer_create(&identity_public_key, 32);
    make_public_key(identity_public_key.ptr, private_key->ptr); // aka IDK
    
    sqrl_protected_memory_create(&site_private_key, private_key->len + identity_public_key.len);
    memcpy(site_private_key->ptr, private_key->ptr, private_key->len);
    memcpy(site_private_key->ptr + private_key->len, identity_public_key.ptr, identity_public_key.len);
    sqrl_protected_memory_free(private_key);
    
    sqrl_trace_buf(sqrl, "Site Private Key: %r\n", site_private_key->ptr, site_private_key->len);
    sqrl_trace_buf(sqrl, "Site Public Key : %r\n", identity_public_key.ptr, identity_public_key.len);
    
    sqrl_base64(&base64_idk, identity_public_key.ptr, identity_public_key.len);
    sqrl_trace(sqrl, "IDK (base64url) : %s\n", base64_idk.str);
    sqrl_strbuf_create_from_string(&body, "ver=1\r\ncmd=query\r\nidk=");
    sqrl_strbuf_append(&body, &base64_idk);
    sqrl_strbuf_append_from_cstr(&body, "\r\n");
    
    sqrl_base64(&base64_client, body.str, body.len);
    sqrl_base64(&base64_server, sqrl_dict_get_string(&request->params, kSqrlUrl), strlen(sqrl_dict_get_string(&request->params, kSqrlUrl)));
    sqrl_strbuf_create_from_string(&buf_to_sign, base64_client.str);
    sqrl_strbuf_append(&buf_to_sign, &base64_server);
    
    sqrl_buffer_create(&ids, 64);
    crypto_signature(ids.ptr, ids.len, (const uint8_t*)buf_to_sign.str, buf_to_sign.len, site_private_key->ptr, site_private_key->len);
    sqrl_protected_memory_free(site_private_key);
    sqrl_base64(&base64_ids, ids.ptr, ids.len);
    
    /* end crypto calculations */
    
    sqrl_strbuf_create_from_string(&request_body, "client=");
    sqrl_strbuf_append(&request_body, &base64_client);
    sqrl_strbuf_append_from_cstr(&request_body, "&server=");
    sqrl_strbuf_append(&request_body, &base64_server);
    sqrl_strbuf_append_from_cstr(&request_body, "&ids=");
    sqrl_strbuf_append(&request_body, &base64_ids);
    
    sqrl_trace(sqrl, "Command Verb    : query\n");
    sqrl_trace(sqrl, "----------------+ Client's parameter list +----------------\n");
    sqrl_trace(sqrl, "ver=1\n");
    sqrl_trace(sqrl, "cmd=query\n");
    sqrl_trace(sqrl, "idk=%s\n", base64_idk.str);
    sqrl_trace(sqrl, "\n-----------------------------------------------------------\n");
    sqrl_trace(sqrl, "'client=' value : %s\n", base64_client.str);
    sqrl_trace(sqrl, "'server=' value : %s\n", base64_server.str);
    sqrl_trace(sqrl, "Buffer to sign  : %s\n", buf_to_sign.str);
    sqrl_trace(sqrl, "IDS (base64url) : %s\n", base64_ids.str);
    sqrl_trace(sqrl, "POST Data String: %s\n", request_body.str);
    
    net_create(&client, "post", sqrl_dict_get_string(&request->params, kHttpUrl));
    
    net_set_header(client, "Host", host.str);
    
    net_set_body(client, request_body.str, request_body.len);
    1/0; // break!!!!!!!!!!!!!!
    //sqrl_impl_server_execute(sqrl, request, response, client);
    
    net_destroy(client);
    
    sqrl_strbuf_release(&host);
    sqrl_strbuf_release(&body);
    sqrl_strbuf_release(&base64_idk);
    sqrl_strbuf_release(&base64_client);
    sqrl_strbuf_release(&base64_server);
    sqrl_strbuf_release(&buf_to_sign);
    sqrl_strbuf_release(&base64_ids);
    sqrl_strbuf_release(&request_body);
    sqrl_buffer_free(&ids);
    sqrl_buffer_free(&identity_public_key);
    
    return result;
}
/*
int sqrl_impl_server_ident(sqrl_impl_t *sqrl, sqrl_server_request_t *request, sqrl_server_response_t *response)
{
    
    return 0;
}*/

/*
 int sqrl_server_query(sqrl_t *impl, const char *utf8_url, const char *utf8_password)
 {
 const size_t buf_sz = 1024;
 char buf[buf_sz];
 uint8_t auth[buf_sz];
 uint8_t ids[buf_sz];
 uint8_t pkey[buf_sz];
 uint8_t *buf_to_sign = 0;
 sqrl_impl_t *sqrl;
 protected_memory_t *pswd, *key, *private_key;
 const char *utf8_url_no_protocol;
 net_client_t *client = 0;
 char *str_b64_server, *str_b64_client, *str_b64_ids;
 int b64_body_len;
 
 utf8_url_no_protocol = get_start_of_host_name(utf8_url);
 
 sqrl = SQRL_CAST(impl);
 sqrl_protected_memory_create(&pswd, 32);
 sqrl_protected_memory_create(&key, 32);
 sqrl_protected_memory_create(&private_key, 32);
 memcpy(key->ptr, sqrl->identity->enc_identity_master, 32);
 
 enscrypt((const uint8_t*)utf8_password, sqrl->identity->scrypt_salt, sizeof(sqrl->identity->scrypt_salt), sqrl->identity->scrypt_n_factor, sqrl->identity->scrypt_iteration_count, pswd->ptr);
 xor_buffer(key->ptr, pswd->ptr, 32);
 sqrl_trace_buf(sqrl, "EnScrypt Result: %r\n", pswd->ptr, pswd->len);
 free_protected_memory(pswd);
 
 hmac(private_key, utf8_url, key);
 free_protected_memory(key);
 
 crypto_signature(auth, 64, (uint8_t*)utf8_url_no_protocol, strlen(utf8_url_no_protocol), private_key->ptr, private_key->len);
 make_public_key(pkey, private_key->ptr);
 
 get_http_url_from_sqrl_url(buf, buf_sz, utf8_url);
 net_create(&client, "post", buf);
 
 const char *b64_idk = base64(pkey, 32, &b64_body_len);
 sprintf(buf, "ver=1\r\ncmd=query\r\nidk=%s", b64_idk);
 str_b64_client = base64(buf, strnlen(buf, buf_sz), &b64_body_len);
 
 str_b64_server = base64(utf8_url, strlen(utf8_url), &b64_body_len);
 
 buf_to_sign = malloc(strlen(str_b64_client) + strlen(str_b64_server));
 memcpy(buf_to_sign, str_b64_client, strlen(str_b64_client));
 memcpy(buf_to_sign + strlen(str_b64_client), str_b64_server, strlen(str_b64_server));
 
 crypto_signature(ids, 64, buf_to_sign, strlen(str_b64_client) + strlen(str_b64_server), auth, 64);
 
 free_protected_memory(private_key);
 
 str_b64_ids = base64(ids, 64, &b64_body_len);
 
 sprintf(buf, "client=%s&server=%s&ids=%s", str_b64_client, str_b64_server, str_b64_ids);
 
 free(str_b64_client);
 free(str_b64_server);
 
 net_set_body(client, (uint8_t*)buf, strnlen(buf, buf_sz));
 
 net_get_host(utf8_url, buf, buf_sz);
 net_set_header(client, "Host", buf);
 net_set_header(client, "User-Agent", "SQRL/1");
 net_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
 
 net_execute(client);
 
 if(net_get_status_code(client) == 200)
 {
 parse_response_body(net_get_body(client), net_get_body_len(client));
 }
 
 net_destroy(client);
 
 return 0;
 }
 */
