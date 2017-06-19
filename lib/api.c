#include "api.h"
#include <stdlib.h>
#include <string.h>
#include "impl.h"
#include "utils.h"
#include "network.h"
#include "base64.h"

int sqrl_init(sqrl_t **sqrl)
{
    *sqrl = malloc(sizeof(sqrl_impl_t));
    if(*sqrl == 0) return 1;
    sqrl_impl_t *impl = SQRL_CAST(*sqrl);
    memset(impl, 0, sizeof(sqrl_impl_t));
    crypto_init(&impl->crypto);
    return 0;
}

void sqrl_destroy(sqrl_t *impl)
{
    sqrl_impl_t *sqrl = SQRL_CAST(impl);
    crypto_free(sqrl->crypto);
    s4_destroy(sqrl->identity);
    free(sqrl);
}

void sqrl_log(sqrl_t *impl, FILE *stm)
{
    sqrl_impl_t *sqrl = SQRL_CAST(impl);
    sqrl->debug_stm = stm;
}

int authenticate_identity(sqrl_impl_t *impl, const char *utf8_password);

int sqrl_identity_load(sqrl_t *impl, FILE *stm, const char *utf8_password)
{
    sqrl_impl_t *sqrl = SQRL_CAST(impl);
    
    if(sqrl->identity)
    {
        s4_destroy(sqrl->identity);
    }
    sqrl->identity = malloc(sizeof(s4_type));
    memset(sqrl->identity, 0, sizeof(s4_type));
    
    if(s4_read(stm, sqrl->identity)) return 1;
    if(sqrl->debug_stm)
    {
        s4_log(sqrl->debug_stm, sqrl->identity);
    }
    if(sqrl->identity->type == 1)
    {
        //sqrl_trace(sqrl, "Skipping S4 Authenitcation\n");
        return authenticate_identity(sqrl, utf8_password);
    }
    return 0;
}

int sqrl_identity_save(sqrl_t *impl, FILE *stm)
{
    sqrl_impl_t *sqrl = SQRL_CAST(impl);
    if(s4_write(stm, sqrl->identity)) return 1;
    return 0;
}

#define SCRYPT_ITER_COUNT 3U
#define SQRL_EOL \r\n

int sqrl_identity_create(sqrl_t *impl)
{
    sqrl_impl_t *sqrl;
    protected_memory_t *identity_unlock_key, *identity_master_key, *gcm_key, *rescue_code;
    uint8_t null_iv[12];
    uint8_t *aad = 0;
    
    sqrl = SQRL_CAST(impl);
    s4_create(&sqrl->identity);
    
    /* Create Identity Unlock Key (IUK) */
    sqrl_protected_memory_create(&identity_unlock_key, 32U);
    memset_random(identity_unlock_key->ptr, identity_unlock_key->len);
    sqrl_trace_buf(sqrl, "IUK: %r\n", identity_unlock_key->ptr, identity_unlock_key->len);
    
    /* Create IMK */
    sqrl_protected_memory_create(&identity_master_key, 32U);
    enhash(identity_master_key->ptr, identity_unlock_key->ptr);
    
    sqrl_trace_buf(sqrl, "IMK: %r\n", identity_master_key->ptr, identity_master_key->len);
    
    /* Create Encrypted Sharable IMK */
    sqrl_protected_memory_create(&gcm_key, 32U);
    memset_random(sqrl->identity->scrypt_salt, sizeof(sqrl->identity->scrypt_salt));
    sqrl_trace_buf(sqrl, "Type1 Salt: %r\n", sqrl->identity->scrypt_salt, sizeof(sqrl->identity->scrypt_salt));
    sqrl->identity->scrypt_n_factor = 9;
    sqrl->identity->scrypt_iteration_count = SCRYPT_ITER_COUNT;
    enscrypt(0, sqrl->identity->scrypt_salt, sizeof(sqrl->identity->scrypt_salt), sqrl->identity->scrypt_n_factor, sqrl->identity->scrypt_iteration_count, gcm_key->ptr);
    sqrl_trace_buf(sqrl, "Type1 GCM Key: %r\n", gcm_key->ptr, gcm_key->len);
    
    memset_random(sqrl->identity->aes_gcm_iv, sizeof(sqrl->identity->aes_gcm_iv));
    
    aad = malloc(sqrl->identity->pt_length);
    s4_get_aad(sqrl->identity, aad);
    gcm_encrypt(sqrl->identity->aes_gcm_iv, sizeof(sqrl->identity->aes_gcm_iv), aad, sqrl->identity->pt_length, gcm_key->ptr, gcm_key->len, identity_master_key->ptr, sqrl->identity->enc_identity_master, identity_master_key->len, sqrl->identity->aes_gcm_verification, sizeof(sqrl->identity->aes_gcm_verification));
    sqrl_protected_memory_free(identity_master_key);
    sqrl_protected_memory_free(gcm_key);
    free(aad);
    
    /* Create Encrypted Identity Unlock Key */
    
    create_rescue_code(&rescue_code);
    sqrl_trace_buf(sqrl, "Rescue Code Buffer: %r\n", rescue_code->ptr, rescue_code->len);
    sqrl_protected_memory_create(&gcm_key, 32U);
    memset_random(sqrl->identity->type2_scrypt_salt, sizeof(sqrl->identity->type2_scrypt_salt));
    sqrl_trace_buf(sqrl, "Type2 Salt: %r\n", sqrl->identity->type2_scrypt_salt, sizeof(sqrl->identity->type2_scrypt_salt));
    sqrl->identity->type2_scrypt_n_factor = 9;
    sqrl->identity->type2_scrypt_iteration_count = SCRYPT_ITER_COUNT;
    enscrypt(rescue_code->ptr, sqrl->identity->type2_scrypt_salt, sizeof(sqrl->identity->type2_scrypt_salt), sqrl->identity->type2_scrypt_n_factor, sqrl->identity->type2_scrypt_iteration_count, gcm_key->ptr);
    sqrl_protected_memory_free(rescue_code);
    sqrl_trace_buf(sqrl, "Type2 GCM Key: %r\n", gcm_key->ptr, gcm_key->len);

    memset_random(sqrl->identity->type2_aes_gcm_verification, sizeof(sqrl->identity->type2_aes_gcm_verification));
    memset(null_iv, 0, sizeof(null_iv));
    gcm_encrypt(null_iv, sizeof(null_iv), 0, 0, gcm_key->ptr, gcm_key->len, identity_unlock_key->ptr, sqrl->identity->type2_enc_identity_unlock, sizeof(sqrl->identity->type2_enc_identity_unlock), sqrl->identity->type2_aes_gcm_verification, sizeof(sqrl->identity->type2_aes_gcm_verification));
    sqrl_protected_memory_free(gcm_key);
    
    /* Create Identity Lock Key */
    make_public_key(sqrl->identity->enc_identity_lock, identity_unlock_key->ptr);
    sqrl_protected_memory_free(identity_unlock_key);
    
    if(sqrl->debug_stm)
    {
        s4_log(sqrl->debug_stm, sqrl->identity);
    }
    
    return 0;
}



/**
 * AES-GCM authentication. Returns zero on success.
 */
int authenticate_identity(sqrl_impl_t *sqrl, const char *password)
{
    int error = 0;
    protected_memory_t *gcm_key = 0;
    protected_memory_t *identity_master = 0;
    uint8_t *aad = 0;
    
    if(sqrl->identity->type != 1) return 0;
    
    aad = malloc(sqrl->identity->pt_length);
    s4_get_aad(sqrl->identity, aad);
    
    sqrl_protected_memory_create(&gcm_key, 32U);
    sqrl_protected_memory_create(&identity_master, 32U);
    
    enscrypt((const uint8_t*)password, sqrl->identity->scrypt_salt, sizeof(sqrl->identity->scrypt_salt), sqrl->identity->scrypt_n_factor, sqrl->identity->scrypt_iteration_count, gcm_key->ptr);
    
    sqrl_trace_buf(sqrl, "GCM Decrypt\n");
    sqrl_trace_buf(sqrl, "\tIV  : %r\n", sqrl->identity->aes_gcm_iv, sizeof(sqrl->identity->aes_gcm_iv));
    sqrl_trace_buf(sqrl, "\tAAD : %r\n", aad, sqrl->identity->pt_length);
    sqrl_trace_buf(sqrl, "\tKEY : %r\n", gcm_key->ptr, gcm_key->len);
    sqrl_trace_buf(sqrl, "\tIMK : %r\n", sqrl->identity->enc_identity_master, identity_master->len);
    sqrl_trace_buf(sqrl, "\tTAG : %r\n", sqrl->identity->aes_gcm_verification, sizeof(sqrl->identity->aes_gcm_verification));
    
    error += gcm_decrypt(sqrl->identity->aes_gcm_iv, sizeof(sqrl->identity->aes_gcm_iv), aad, sqrl->identity->pt_length, gcm_key->ptr, gcm_key->len, sqrl->identity->enc_identity_master, identity_master->ptr, identity_master->len, sqrl->identity->aes_gcm_verification, sizeof(sqrl->identity->aes_gcm_verification));
    
//    error += gcm_decrypt(sqrl->identity->aes_gcm_iv, sizeof(sqrl->identity->aes_gcm_iv), aad, sqrl->identity->pt_length, gcm_key->ptr, gcm_key->len, sqrl->identity->enc_identity_lock, identity_master->ptr, identity_master->len, sqrl->identity->aes_gcm_verification, sizeof(sqrl->identity->aes_gcm_verification));
//
//    error += gcm_decrypt(sqrl->identity->aes_gcm_iv, sizeof(sqrl->identity->aes_gcm_iv), aad, sqrl->identity->pt_length, gcm_key->ptr, gcm_key->len, sqrl->identity->enc_prev_identity_unlock, identity_master->ptr, identity_master->len, sqrl->identity->aes_gcm_verification, sizeof(sqrl->identity->aes_gcm_verification));
    
    sqrl_protected_memory_free(gcm_key);
    sqrl_protected_memory_free(identity_master);
    free(aad);

    return error;
}

//int sqrl_server_query(sqrl_t *impl, const char *utf8_url)
//{
//    const size_t buf_sz = 1024;
//    char buf[buf_sz];
//    net_client_t *client = 0;
//    char *str_b64_server;
//    char *str_b64_client;
//    int b64_body_len;
//    
//    if(strncmp(utf8_url, "sqrl://", 7) == 0)
//    {
//        sprintf(buf, "https%s", utf8_url + 4);
//    }
//    else if(strncmp(utf8_url, "qrl://", 6) == 0)
//    {
//        sprintf(buf, "http%s", utf8_url + 3);
//    }
//    else
//    {
//        return 1;
//    }
//    
//    net_create(&client, "post", buf);
//    
//    sprintf(buf, "ver=1\r\ncmd=query\r\n");
//    str_b64_client = base64(buf, strnlen(buf, buf_sz), &b64_body_len);
//    
//    str_b64_server = base64(utf8_url, strlen(utf8_url), &b64_body_len);
//    
//    sprintf(buf, "client=%s&server=%s", str_b64_client, str_b64_server);
//    free(str_b64_client);
//    free(str_b64_server);
//    
//    net_set_body(client, (uint8_t*)buf, strnlen(buf, buf_sz));
//    
//    net_get_host(utf8_url, buf, buf_sz);
//    net_set_header(client, "Host", buf);
//    net_set_header(client, "User-Agent", "SQRL/1");
//    net_set_header(client, "Content-Type", "application/x-www-form-urlencoded");
//    
//    net_execute(client);
//    
//    net_destroy(client);
//    
//    return 0;
//}

void parse_response_body(const uint8_t *body, size_t len);
// returns -1 if not valid sqrl url
const char* get_start_of_host_name(const char *utf8_url);
// buf will contain zero terminated url
// returns zero on success
int get_http_url_from_sqrl_url(char *buf, size_t buf_sz, const char* utf8_url);

// query, indent, disable, enable, remove, ask

int hmac(protected_memory_t *private_key, const char *utf8_url, const protected_memory_t *key);

/*
int sqrl_server_associate(sqrl_t *impl, const char *utf8_url, const char *utf8_password)
{
    const size_t buf_sz = 1024;
    char buf[buf_sz];
    uint8_t auth[buf_sz];
    uint8_t pkey[buf_sz];
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
    free_protected_memory(pswd);
    
    hmac(private_key, utf8_url, key);
    free_protected_memory(key);
    
    crypto_signature(auth, 64, (uint8_t*)utf8_url_no_protocol, strlen(utf8_url_no_protocol), private_key->ptr, private_key->len);
    make_public_key(pkey, private_key->ptr);
    free_protected_memory(private_key);
    
    get_http_url_from_sqrl_url(buf, buf_sz, utf8_url);
    net_create(&client, "post", buf);
    
    const char *b64_idk = base64(pkey, 32, &b64_body_len);
    sprintf(buf, "ver=1\r\ncmd=create\r\nidk=%s", b64_idk);
    str_b64_client = base64(buf, strnlen(buf, buf_sz), &b64_body_len);
    
    str_b64_server = base64(utf8_url, strlen(utf8_url), &b64_body_len);
    
    str_b64_ids = base64(auth, 64, &b64_body_len);
    
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

int sqrl_server_associate(sqrl_t *impl, const char *utf8_url, const char *utf8_password)
{
    if(!impl) return 1;
    if(!utf8_url) return 1;
    
    sqrl_impl_t *sqrl = SQRL_CAST(impl);
    return sqrl_impl_server_associate(sqrl, utf8_url, utf8_password);
}

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

int get_http_url_from_sqrl_url(char *buf, size_t buf_sz, const char* utf8_url)
{
    if(buf_sz < strlen(utf8_url) + 1) return 1;
    
    if(strncmp(utf8_url, "sqrl://", 7) == 0)
    {
        sprintf(buf, "https%s", utf8_url + 4);
    }
    else if(strncmp(utf8_url, "qrl://", 6) == 0)
    {
        sprintf(buf, "http%s", utf8_url + 3);
    }
    else
    {
        return 2;
    }
    return 0;
}

//int hmac(protected_memory_t *private_key, const char *utf8_url, const protected_memory_t *key)
//{
//    const size_t buf_sz = 256;
//    uint8_t buf[buf_sz];
//    net_get_host(utf8_url, (char*)buf, buf_sz);
//    return sqrl_crypto_hmac(private_key->ptr, buf, strnlen((char*)buf, buf_sz), key->ptr);
//}

const char* get_start_of_host_name(const char *utf8_url)
{
    const char *utf8_url_no_protocol = -1;
    if(strncasecmp(utf8_url, "sqrl", 4) == 0) utf8_url_no_protocol = utf8_url + 7;
    else if(strncasecmp(utf8_url, "qrl", 3) == 0) utf8_url_no_protocol = utf8_url + 6;
    return utf8_url_no_protocol;
}

//void parse_response_body(const uint8_t *b64_body, size_t b64_body_len)
//{
//    int body_len;
//    uint8_t *body;
//    char *token, *value;
//    size_t str_len;
//    body = unbase64((const char*)b64_body, b64_body_len, &body_len);
//    
//    token = strtok((char*)body, "\r\n");
//    while(token)
//    {
//        value = strchr(token, '=');
//        if(value)
//        {
//            str_len = strlen(value);
//            if(str_len > 1)
//            {
//                *value = 0; value++;
//                fprintf(stdout, "%s=%s\n", token, value);
//            }
//            
//        }
//        token = strtok(0, "\r\n");
//    }
//    
//    free(body);
//}

