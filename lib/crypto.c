#include "crypto.h"
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
//#include "scrypt/lib/crypto/crypto_scrypt.h"
#include "aes-gcm/gcm.h"

struct crypto_impl_t {
    
};
typedef struct crypto_impl_t crypto_impl;
#define CRYPTO_CAST(p) (crypto_impl*)p

int crypto_init(crypto_t **crypto)
{
    *crypto = malloc(sizeof(crypto_impl));
    if(*crypto == 0) return 1;
    if(sodium_init()) return 1;
    if(gcm_initialize()) return 1;
    return 0;
}

void crypto_free(crypto_t *crypto)
{
    free(crypto);
}

void sqrl_protected_memory_create(protected_memory_t **mem, size_t size)
{
    (*mem) = malloc(sizeof(protected_memory_t));
    memset(*mem, 0, sizeof(protected_memory_t));
    (*mem)->ptr = sodium_malloc(size);
    if ((*mem)->ptr)
    {
        (*mem)->len = size;
        sodium_mlock((*mem)->ptr, (*mem)->len);
        sodium_memzero((*mem)->ptr, (*mem)->len);
    }
}

void sqrl_protected_memory_free(protected_memory_t *mem)
{
    if(!mem) return;
    sodium_munlock(mem->ptr, mem->len);
    sodium_free(mem->ptr);
    free(mem);
}

void memset_random(void * const buf, size_t sz)
{
    // use libsodium
    randombytes_buf(buf, sz);
}

void create_rescue_code(protected_memory_t **mem)
{
    // TODO : sg uses a full 256bit random buffer to generate rescue code
    uint8_t *ptr = 0;
    sqrl_protected_memory_create(mem, 25);
    ptr = (*mem)->ptr;
    for(unsigned i = 0; i < 24; ++i, ++ptr)
    {
        uint32_t decimal = randombytes_uniform(10);
        *ptr = '0' + decimal;
    }
    *ptr = 0; // null terminate
    printf("Rescue Code: ");
    const char *cptr = (*mem)->ptr;
    for(unsigned i = 0; i < 24; ++i, ++cptr)
    {
        if(i > 0 && i % 4 == 0)
        {
            printf("-");
        }
        printf("%c", *cptr);
    }
    printf("\n");
}

int enscrypt(const uint8_t *utf8_passwd, const uint8_t *salt, size_t salt_len, uint8_t n_factor, uint32_t iterations, uint8_t *buf)
{
    size_t passwd_len;
    uint8_t salt_temp[32];
    uint8_t xor_temp[32];
    uint64_t N;
    
    passwd_len = 0;
    N = 1 << n_factor;
    
    if(!buf) return -1;
    
    memset(buf, 0, 32);
    memset(salt_temp, 0, sizeof(salt_temp));
    memset(xor_temp, 0, sizeof(xor_temp));
    
    if(utf8_passwd)
    {
        passwd_len = strlen((const char*)utf8_passwd);
    }
    if(salt)
    {
        memcpy(salt_temp, salt, salt_len);
        salt_len = 32;
    }

    if(iterations == 1)
    {
        return crypto_pwhash_scryptsalsa208sha256_ll(utf8_passwd, passwd_len, salt_temp, salt_len, N, 256, 1, buf, 32);
    }
    
    if(crypto_pwhash_scryptsalsa208sha256_ll(utf8_passwd, passwd_len, salt_temp, salt_len, N, 256, 1, buf, 32)) return -1;
    memcpy(salt_temp, buf, 32);
    memcpy(xor_temp, buf, 32);
    salt_len = 32;
    --iterations;
    for(; iterations > 0; --iterations)
    {
        if(crypto_pwhash_scryptsalsa208sha256_ll(utf8_passwd, passwd_len, salt_temp, salt_len, N, 256, 1, xor_temp, 32)) return -1;
        memcpy(salt_temp, xor_temp, 32);
        xor_buffer(buf, xor_temp, 32);
    }
    
    return 0;
}

int enhash(uint8_t *out, const uint8_t *in)
{
    uint8_t xor_buf[32];
    uint8_t prev_buf[32];
    crypto_hash_sha256(out, in, 32);
    memcpy(xor_buf, out, 32);
    memcpy(prev_buf, out, 32);
    for(int index = 0; index < 15; ++index)
    {
        crypto_hash_sha256(out, prev_buf, 32);
        memcpy(prev_buf, out, 32);
        xor_buffer(xor_buf, prev_buf, 32);
    }
    memcpy(out, xor_buf, 32);
    return 0;
}

void xor_buffer(uint8_t *dst, const uint8_t *src, size_t count)
{
    for(size_t index = 0; index < count; ++index)
    {
        dst[index] = dst[index] ^ src[index];
    }
}

int gcm_encrypt(const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len, const uint8_t *key, size_t key_len, const uint8_t *input, uint8_t *output, size_t length, uint8_t *tag, size_t tag_len)
{
    gcm_context ctx;
    int error = 0;
    error = gcm_setkey(&ctx, key, key_len);
    if(!error) error = gcm_crypt_and_tag(&ctx, ENCRYPT, iv, iv_len, aad, aad_len, input, output, length, tag, tag_len);
    gcm_zero_ctx(&ctx);
    return error;
}

int gcm_decrypt(const uint8_t *iv, size_t iv_len, const uint8_t *aad, size_t aad_len, const uint8_t *key, size_t key_len, const uint8_t *input, uint8_t *output, size_t length, uint8_t *tag, size_t tag_len)
{
    gcm_context ctx;
    int error = 0;
    error = gcm_setkey(&ctx, key, key_len);
    if(!error) error = gcm_auth_decrypt(&ctx, iv, iv_len, aad, aad_len, input, output, length, tag, tag_len);
    gcm_zero_ctx(&ctx);
    if(GCM_AUTH_FAILURE == error)
    {
        fprintf(stderr, "GCM_AUTH_FAILURE\n");
    }
    return error;
}

// WHY are these the same!!!!
int make_public_key(uint8_t *public_key, const uint8_t *seed)
{
    int res = 0;
    
    protected_memory_t *ed25519_pk = 0;
    sqrl_protected_memory_create(&ed25519_pk, crypto_sign_SECRETKEYBYTES);
    sign_public(ed25519_pk->ptr, seed);
    crypto_sign_ed25519_pk_to_curve25519(public_key, ed25519_pk->ptr);
    
    sqrl_protected_memory_free(ed25519_pk);
    
    return res;
}

int sign_public(uint8_t *public_key, const uint8_t *seed)
{
    // https://www.grc.com/sqrl/idlock.htm
    // The “SignPublic” function is the “crypto_sign_seed_keypair” function from LibSodium. It is part of the Curve25519 elliptic curve cryptosystem which converts a 256-bit “seed” into a pair of signing keys: a private
    // signing key and a public signature verification key. The VerifyUnlock key is the public signature verification key produced by that function.
    int res = 0;
    // use protected memory so as not to leak ignored private key
    protected_memory_t *temp = 0;
    sqrl_protected_memory_create(&temp, crypto_sign_SECRETKEYBYTES);
    res = crypto_sign_ed25519_seed_keypair(public_key, temp->ptr, seed);
    sqrl_protected_memory_free(temp);
    return res;
}

int crypto_signature(uint8_t *out, size_t out_len, const uint8_t *msg, size_t msg_len, const uint8_t *key, size_t key_len)
{
    unsigned long long siglen_p = 0;
//    protected_memory_t *ed25519_pk = 0;
    
    if(out_len != 64 || key_len != 64) return -1;
    
//    sqrl_protected_memory_create(&ed25519_pk, crypto_sign_SECRETKEYBYTES);
//    crypto_sign_ed25519_detached(ed25519_pk->ptr, &siglen_p, msg, msg_len, key);
//    crypto_sign_ed25519_pk_to_curve25519(out, ed25519_pk->ptr);
//    sqrl_protected_memory_free(ed25519_pk);
//    
//    return 0;
    
    return crypto_sign_ed25519_detached(out, &siglen_p, msg, msg_len, key);
}

int sqrl_crypto_hmac(uint8_t *out, const uint8_t *msg, size_t msg_len, const uint8_t *k)
{
    return crypto_auth_hmacsha256(out, msg, msg_len, k);
    //return crypto_auth_hmacsha256_verify(out, msg, msg_len, k);
}

int sqrl_crypto_dhka_create_public_key(uint8_t *out, const uint8_t *private_key)
{
    return crypto_scalarmult_base(out, private_key);
}

int sqrl_crypto_dhka(uint8_t *out, const uint8_t *private_key, const uint8_t *public_key)
{
    return crypto_scalarmult(out, private_key, public_key);
}
