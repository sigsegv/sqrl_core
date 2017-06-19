#include "network.h"
#include <CoreFoundation/CoreFoundation.h>
#include <CoreServices/CoreServices.h>

struct net_impl_t {
    CFURLRef url;
    CFHTTPMessageRef request;
    CFHTTPMessageRef response;
    CFDataRef body;
};
typedef struct net_impl_t net_impl;
#define SQRL_NET_CAST(p) (net_impl*)p

#define SQRL_CF_SAFE_RELEASE(cf) if(cf != NULL) { CFRelease(cf); cf = NULL; }

// don't forget to release returned CStringRef!!!
CFStringRef utf8_to_str(const char *utf8_str)
{
	return CFStringCreateWithCString(kCFAllocatorDefault, utf8_str, kCFStringEncodingUTF8);
}

size_t str_to_utf8(CFStringRef source, char *buf, size_t buf_len)
{
    CFIndex uni_length = CFStringGetLength(source);
    CFIndex max_utf8_len = CFStringGetMaximumSizeForEncoding(uni_length, kCFStringEncodingUTF8);
    if(buf_len < max_utf8_len + 1) return 0;
    CFStringGetCString(source, buf, max_utf8_len, kCFStringEncodingUTF8);
    return strnlen(buf, max_utf8_len);
}

size_t sqrl_str_to_utf8(CFStringRef source, sqrl_strbuf_t *buf)
{
    CFIndex uni_length = CFStringGetLength(source);
    CFIndex max_utf8_len = CFStringGetMaximumSizeForEncoding(uni_length, kCFStringEncodingUTF8);
    sqrl_strbuf_grow(buf, max_utf8_len + 1);
    CFStringGetCString(source, buf->str, max_utf8_len, kCFStringEncodingUTF8);
    buf->len = strnlen(buf->str, max_utf8_len);
    return buf->len;
}

void LogResponseHeaders(const void* name, const void* value, void* context)
{
    const size_t buf_sz = 256;
    char name_buf[buf_sz];
    char value_buf[buf_sz];
    
    CFStringRef cfstr_name = (CFStringRef)name;
    CFStringRef cfstr_value = (CFStringRef)value;
    str_to_utf8(cfstr_name, name_buf, buf_sz);
    str_to_utf8(cfstr_value, value_buf, buf_sz);
    fprintf(stderr, "%s:%s\n", name_buf, value_buf);
}

void ReadResponseHeaders(const void* name, const void* value, void* context)
{
    sqrl_strbuf_t name_buf = SQRL_STRBUF_INIT;
    sqrl_strbuf_t value_buf = SQRL_STRBUF_INIT;
    sqrl_dict_t *dict = (sqrl_dict_t*)context;
    
    CFStringRef cfstr_name = (CFStringRef)name;
    CFStringRef cfstr_value = (CFStringRef)value;
    sqrl_str_to_utf8(cfstr_name, &name_buf);
    sqrl_str_to_utf8(cfstr_value, &value_buf);
    sqrl_dict_add(dict, name_buf.str, value_buf.str);
    
    sqrl_strbuf_release(&name_buf);
    sqrl_strbuf_release(&value_buf);
}

void net_create(net_client_t **client, const char *utf8_method, const char *utf8_url)
{
    net_impl *impl = 0;
    CFStringRef method_str = 0;
	CFStringRef url_str = 0;
    
    *client = (net_client_t*)malloc(sizeof(net_impl));
    impl = SQRL_NET_CAST(*client);
    method_str = utf8_to_str(utf8_method);
	url_str = utf8_to_str(utf8_url);
	impl->url = CFURLCreateWithString(kCFAllocatorDefault, url_str, NULL);
    impl->request = CFHTTPMessageCreateRequest(kCFAllocatorDefault, method_str, impl->url, kCFHTTPVersion1_1);
    impl->response = 0;

    SQRL_CF_SAFE_RELEASE(method_str);
    SQRL_CF_SAFE_RELEASE(url_str);
}

void net_destroy(net_client_t *client)
{
    net_impl *impl = SQRL_NET_CAST(client);
    SQRL_CF_SAFE_RELEASE(impl->url);
    SQRL_CF_SAFE_RELEASE(impl->request);
    SQRL_CF_SAFE_RELEASE(impl->response);
    SQRL_CF_SAFE_RELEASE(impl->body);
    free(impl);
}

int sqrl_net_get_host(const char *utf8_url, sqrl_strbuf_t *buf)
{
	CFStringRef url_str = 0;
    CFStringRef host = 0;
    CFURLRef url = 0;
    int success = 0;
    
    url_str = utf8_to_str(utf8_url);
	url = CFURLCreateWithString(kCFAllocatorDefault, url_str, NULL);
    host = CFURLCopyHostName(url);
    success = sqrl_str_to_utf8(host, buf);
    
    SQRL_CF_SAFE_RELEASE(host);
    SQRL_CF_SAFE_RELEASE(url);
    SQRL_CF_SAFE_RELEASE(url_str);
    
    return success;
}

int sqrl_net_is_secure(const char *utf8_url)
{
    CFStringRef url_str = 0;
    CFStringRef scheme = 0;
    CFURLRef url = 0;
    CFComparisonResult result;
    int secure = 0;
    
    url_str = utf8_to_str(utf8_url);
    url = CFURLCreateWithString(kCFAllocatorDefault, url_str, NULL);
    scheme = CFURLCopyScheme(url);
    
    result = CFStringCompareWithOptions(scheme, CFSTR("sqrl"), CFRangeMake(0, CFStringGetLength(scheme)), kCFCompareCaseInsensitive);
    secure = kCFCompareEqualTo == result;
    
    SQRL_CF_SAFE_RELEASE(scheme);
    SQRL_CF_SAFE_RELEASE(url);
    SQRL_CF_SAFE_RELEASE(url_str);
    
    return secure;
}

int sqrl_net_get_query_params(const char *utf8_url, sqrl_dict_t *query_out)
{
    sqrl_strbuf_t buf = SQRL_STRBUF_INIT;
    char *token, *value;
    size_t str_len;
    CFStringRef url_str = 0;
    CFStringRef query = 0;
    CFURLRef url = 0;
    int success = 0;
    
    url_str = utf8_to_str(utf8_url);
    url = CFURLCreateWithString(kCFAllocatorDefault, url_str, NULL);
    query = CFURLCopyQueryString(url, CFSTR(""));
    
    sqrl_str_to_utf8(query, &buf);
    token = strtok((char*)buf.str, "&");
    while(token)
    {
        value = strchr(token, '=');
        if(value)
        {
            str_len = strlen(value);
            if(str_len > 1)
            {
                *value = 0; ++value; // mark '=' as null, and skip
                sqrl_dict_add(query_out, token, value);
            }
        }
        token = strtok(0, "&");
    }
    
    SQRL_CF_SAFE_RELEASE(query);
    SQRL_CF_SAFE_RELEASE(url);
    SQRL_CF_SAFE_RELEASE(url_str);
    sqrl_strbuf_release(&buf);
    
    return success;
}

int sqrl_net_get_url_resource(const char *utf8_url, sqrl_strbuf_t *url_resource)
{
    CFStringRef url_str = 0;
    CFStringRef resource = 0;
    CFURLRef url = 0;
    int secure = 0;
    
    url_str = utf8_to_str(utf8_url);
    url = CFURLCreateWithString(kCFAllocatorDefault, url_str, NULL);
    resource = CFURLCopyPath(url);
    
    sqrl_str_to_utf8(resource, url_resource);
    
    SQRL_CF_SAFE_RELEASE(resource);
    SQRL_CF_SAFE_RELEASE(url);
    SQRL_CF_SAFE_RELEASE(url_str);
    
    return secure;
}

/*
int sqrl_net_get_authenticating_domain(const char *utf8_url, sqrl_strbuf_t *buf)
{
    int result = 0;
    CFStringRef url_str = 0;
    CFStringRef scheme = 0;
    CFStringRef host = 0;
    CFStringRef path = 0;
    CFStringRef query = 0;
    CFStringRef username = 0;
    CFStringRef password = 0;
    CFURLRef url = 0;
    
    url_str = utf8_to_str(utf8_url);
    url = CFURLCreateWithString(kCFAllocatorDefault, url_str, NULL);
    
    //result = CFURLCanBeDecomposed(url) == true ? 1 : 0;
    
    scheme = CFURLCopyScheme(url);
    host = CFURLCopyHostName(url);
    username = CFURLCopyUserName(url);
    password = CFURLCopyPassword(url);
    path = CFURLCopyNetLocation(url);
    
    
    return result;
}*/

int net_set_header(net_client_t *client, const char *utf8_name, const char *utf8_value)
{
    CFStringRef name = 0;
    CFStringRef value = 0;
    net_impl *impl = SQRL_NET_CAST(client);
    
    name = utf8_to_str(utf8_name);
    value = utf8_to_str(utf8_value);
    CFHTTPMessageSetHeaderFieldValue(impl->request, name, value);
    
    SQRL_CF_SAFE_RELEASE(name);
    SQRL_CF_SAFE_RELEASE(value);

    return 0;
}

int net_set_body(net_client_t *client, const void *body, size_t body_len)
{
    CFDataRef data = 0;
    net_impl *impl = SQRL_NET_CAST(client);
    
    data = CFDataCreate(kCFAllocatorDefault, body, body_len);
    CFHTTPMessageSetBody(impl->request, data);
    
    SQRL_CF_SAFE_RELEASE(data);
    
    return 0;
}

int net_execute(net_client_t *client)
{
    uint32_t status = 400;
    const size_t nBuffSize = 4096;
    UInt8 buff[nBuffSize];
    net_impl *impl = SQRL_NET_CAST(client);
    CFReadStreamRef readStream = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, impl->request);
    CFReadStreamSetProperty(readStream, kCFStreamPropertyHTTPShouldAutoredirect, kCFBooleanTrue); // yes, disable redirection
    
    if(CFReadStreamOpen(readStream))
    {
        
        
        CFMutableDataRef body = CFDataCreateMutable(kCFAllocatorDefault, 0);
        CFIndex numBytesRead;
        
        // copy response bytes from stream to response
        do {
            numBytesRead = CFReadStreamRead(readStream, buff, nBuffSize);
            if( numBytesRead > 0 )
            {
                CFDataAppendBytes(body, buff, numBytesRead);
            }
            else if( numBytesRead < 0 )
            {
                CFErrorRef error = CFReadStreamCopyError(readStream);
                if(error)
                {
                    CFStringRef err_msg = CFErrorCopyDescription(error);
                    str_to_utf8(err_msg, (char*)buff, nBuffSize);
					SQRL_CF_SAFE_RELEASE(err_msg);
					SQRL_CF_SAFE_RELEASE(error);
                }
            }
        } while ( numBytesRead > 0 );
        
        impl->response = (CFHTTPMessageRef)CFReadStreamCopyProperty(readStream, kCFStreamPropertyHTTPResponseHeader);
        if(impl->response)
        {
            CFHTTPMessageSetBody(impl->response, (CFDataRef)body);
            status = CFHTTPMessageGetResponseStatusCode(impl->response);
            CFStringRef statusLine = CFHTTPMessageCopyResponseStatusLine(impl->response);
            if(statusLine && CFStringGetLength(statusLine))
            {
                //response_msg = std::string(CFStringGetCStringPtr(statusLine, kCFStringEncodingUTF8));
                //str_to_utf8(statusLine, buff, nBuffSize);
            }
            
            impl->body = CFHTTPMessageCopyBody(impl->response);
            if(impl->body)
            {
                CFIndex body_length = CFDataGetLength(impl->body);
                //response_body.resize(body_length);
                const UInt8 *ptr = CFDataGetBytePtr(impl->body);
                memcpy(buff, ptr, body_length);
                buff[body_length] = 0;
                fprintf(stderr, "%s\n", buff);
            }
        }
        CFReadStreamClose(readStream);
    }
    SQRL_CF_SAFE_RELEASE(readStream);
    
    return 0;
}

uint32_t net_get_status_code(net_client_t *client)
{
    net_impl *impl = SQRL_NET_CAST(client);
    return CFHTTPMessageGetResponseStatusCode(impl->response);
}

const uint8_t* net_get_body(net_client_t *client)
{
    net_impl *impl = SQRL_NET_CAST(client);
    return CFDataGetBytePtr(impl->body);
}

size_t net_get_body_len(net_client_t *client)
{
    net_impl *impl = SQRL_NET_CAST(client);
    return CFDataGetLength(impl->body);
}

void net_get_headers(net_client_t *client, sqrl_dict_t *dict)
{
    net_impl *impl = SQRL_NET_CAST(client);
    CFDictionaryRef headers = CFHTTPMessageCopyAllHeaderFields(impl->response);
    CFDictionaryApplyFunction(headers, ReadResponseHeaders, dict);
}


