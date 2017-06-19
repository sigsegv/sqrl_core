#ifndef CRYPTO_H
#define CRYPTO_H

#include <stdio.h>
#include <stdint.h>
#include "utils.h"

struct crypto_typ;
typedef struct crypto_typ crypto_t;

/**
 * Initialize Crypto resources.
 *
 * @return zero on success, otherwise error
 */
int crypto_init(crypto_t **crypto);

/**
 * Destroy any crypto resources
 */
void crypto_free(crypto_t *crypto);

struct protected_memory_typ {
    void *ptr;
    size_t len;
};
typedef struct protected_memory_typ protected_memory_t;

/**
 * allocate memory and protect memory
 */
void sqrl_protected_memory_create(protected_memory_t **mem, size_t size);
/**
 * zero and free memory
 */
void sqrl_protected_memory_free(protected_memory_t *mem);

/**
 * Fill 'buf' of size 'sz' with random bytes
 */
void memset_random(void * const buf, size_t sz);

/**
 * make_rescue_code allocates the memory, but
 * caller takes responsibility for properly freeing 'mem'
 *
 * mem will be a null-terminated ascii string containing
 * the decimal values of the rescue code.
 *
 * For example
 *
 * 2710-9930-0985-8020-7689-9115 (dashes shown for convenience)
 *
 * @param mem uninitialize/unallocated pointer. Caller takes ownership
 */
void create_rescue_code(protected_memory_t **mem);

/**
 * enscrypt : SQRL enhanced SCrypt (PBKDF2 based)
 *
 * n is the n-factor from S4
 * salt, if specified, must be 16-byte case insensitive hexadecimal, otherwise pass in zero
 * password, if specified, is null-terminated UTF-8 string, otherwise, pass in zero
 *
 * buf MUST be 32 bytes in size
 *
 * @param utf8_passwd (optional) if not null, then a null terminated utf8 string
 * @param salt 128b salt
 * @param n_factor memory consumption factor
 * @param iterations time consumption factor
 * @param buf 256b output buffer
 *
 * Return 0 on success; or -1 on error.
 */
int enscrypt(const uint8_t *utf8_passwd, const uint8_t *salt, size_t salt_len, uint8_t n_factor, uint32_t iterations, uint8_t *buf);

/**
 * enhash : SQRL enhanced hashing
 *
 * in : 256 bit buffer containing value to hash
 * out : resulting hash output
 * return 0 on sucess; or -1 on error.
 */
int enhash(uint8_t *out, const uint8_t *in);

/**
 * xor dst and src, updating dst with the result
 */
void xor_buffer(uint8_t *dst, const uint8_t *src, size_t count);

int gcm_encrypt(const uint8_t *iv, size_t iv_len, const uint8_t * aad, size_t aad_len, const uint8_t *key, size_t key_len, const uint8_t *input, uint8_t *output, size_t length, uint8_t *tag, size_t tag_len);

int gcm_decrypt(const uint8_t *iv, size_t iv_len, const uint8_t * aad, size_t aad_len, const uint8_t *key, size_t key_len, const uint8_t *input, uint8_t *output, size_t length, uint8_t *tag, size_t tag_len);

/**
 * Create public key from private key
 *
 * @param public_key 256b buffer to which public key is written to
 * @param seed 256b seed to create public key
 * @return zero on success
 */
int make_public_key(uint8_t *public_key, const uint8_t *seed);

/**
 * 
 * @param public_key 256b buffer for public key
 * @param seed 256b buffer that forms seed to create public key
 */
int sign_public(uint8_t *public_key, const uint8_t *seed);

/**
 * Create Identity Authentication (hash)
 *
 * @param out buffer to which hashed authentication data is written to
 * @param out_len target size
 * @param msg message to hash
 * @param msg_len length of message to hash
 * @param key key to use for hashing
 * @param key_len length of hash key
 *
 * @return zero on success
 */
int crypto_signature(uint8_t *out, size_t out_len, const uint8_t *msg, size_t msg_len, const uint8_t *key, size_t key_len);

/**
 * Authenticates message msg, whose length is in_len, using secret key k
 *
 * @param out 256b buffer for authenticator
 * @param msg message to be authenticated
 * @param msg_len length of message
 * @param k 256b buffer containing private key
 *
 * @return zero on success
 */
int sqrl_crypto_hmac(uint8_t *out, const uint8_t *msg, size_t msg_len, const uint8_t *k);

/**
 * Generate public key from private key
 *
 * @param out 256b buffer for public key
 * @param private_key 256b buffer containing private
 */
int sqrl_crypto_dhka_create_public_key(uint8_t *out, const uint8_t *private_key);

/**
 * Compute shared secret
 *
 * @param out 256b buffer for shared secret
 * @param private_key 256b private key
 * @param public_key 256b public key
 */
int sqrl_crypto_dhka(uint8_t *out, const uint8_t *private_key, const uint8_t *public_key);

#endif