#ifndef S4_H
#define S4_H

#include <stdint.h>
#include <stdio.h>

struct s4_data_t {
    // Type1
    uint16_t length;
    uint16_t type;
    uint16_t pt_length;
    uint8_t aes_gcm_iv[12];
    uint8_t scrypt_salt[16];
    uint8_t scrypt_n_factor;
    uint32_t scrypt_iteration_count;
    uint16_t flags;
    uint8_t hint_length;
    uint8_t pw_verify_sec;
    uint16_t idle_timeout_min;
    uint8_t enc_identity_master[32];
    uint8_t enc_identity_lock[32];
    uint8_t enc_prev_identity_unlock[32];
    uint8_t aes_gcm_verification[16];
    // Type2
    uint16_t type2_length;
    uint8_t type2_scrypt_salt[16];
    uint8_t type2_scrypt_n_factor;
    uint32_t type2_scrypt_iteration_count;
    uint8_t type2_enc_identity_unlock[32];
    uint8_t type2_aes_gcm_verification[16];
};
typedef struct s4_data_t s4_type;

enum s4_flag {
    e_s4_check_for_updates =    0x0001,
    e_s4_always_ask_identity =  0x0002,
    e_s4_sqrl_only =            0x0004,
    e_s4_hard_lock =            0x0008,
    e_s4_warn_mitm =            0x0010,
    e_s4_discard_on_suspend =   0x0020,
    e_s4_discard_on_switch =    0x0040,
    e_s4_discard_on_idle =      0x0080
};

void s4_create(s4_type **data);
void s4_init(s4_type *data);
void s4_destroy(s4_type *data);

/**
 * Read SQRL Secure Storage System (S4)
 *
 * @param stm the input stream.
 * @param s4_data the data object to fill in.
 *
 * @return @return zero on success, otherwise error
 */
int s4_read(FILE *stm, s4_type *data);

/**
 * Read SQRL Secure Storage System (S4)
 *
 * @param stm the output stream.
 * @param s4_data the data object to write from.
 *
 * @return @return zero on success, otherwise error
 */
int s4_write(FILE *stm, s4_type *data);

void s4_set_flag(s4_type *data, enum s4_flag flag);

/**
 * Fill in aad with Additional Authenticated Data from
 * Type1 S4 data.
 *
 * @param aad must be sizeof == pt_length value
 */
void s4_get_aad(s4_type *data, uint8_t *aad);

/**
 * Write out logging details to stm
 */
void s4_log(FILE *stm, s4_type *data);

#endif