#include "S4.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "utils.h"

/*************************************************************************
 * in stdint.h uint32_T is defined as unsigned int, which according to k&r can be as little as 2 bytes!
 * We need at least 4 bytes, which I think any modern compiler is, but to be safe...
 ************************************************************************/
#if UINT_MAX < UINT32_MAX
#error uint32_t type appears to be (probably) 2 bytes. We need 4
#endif

#define FREAD_ZERO_ON_SUCCESS(buffer, size, count, stream) ()
#define FWRITE_ZERO_ON_SUCCESS(buffer, size, count, stream) ()

/**
 * return zero on success
 */
int get_s4_bytes(uint8_t *ptr, FILE *source, size_t count, uint8_t is_binary)
{
    // TODO handle non-binary version
    if(!is_binary) return 1;
    
    return fread(ptr, 1, count, source) == count ? 0 : 1;
}

/**
 * determine format(binary or 6-bit base64url encoded), length, and type
 *
 * return non-zero if any error
 */
int read_header(FILE *source, uint16_t *type, uint8_t *is_binary, uint16_t *length)
{
    char *cptr = 0;
    const size_t kHeaderSize = 8;
    const size_t kLengthSize = 2;
    uint8_t buf[kHeaderSize];
    
    *type = 0;
    *is_binary = 1;
    *length = 0;
    
    // Confirm sqrldata and if binary or
    if(get_s4_bytes(buf, source, kHeaderSize, *is_binary)) return 1;
    
    cptr = (char*)buf;
    
    if(strncmp(cptr, "sqrldata", kHeaderSize) == 0)
    {
        *is_binary = 1;
    }
    else if(strncmp(cptr, "SQRLDATA", kHeaderSize) == 0)
    {
        *is_binary = 0;
    }
    else
    {
        return 1;
    }
    
    if(get_s4_bytes((uint8_t*)length, source, kLengthSize, *is_binary)) return 1;
    
    return get_s4_bytes((uint8_t*)type, source, kLengthSize, *is_binary);
}

void skip_unsupported_section(FILE *source, s4_type *s4_data)
{
    uint16_t bytes_to_skip = 0;
    if(s4_data->pt_length <= 45) return;
    bytes_to_skip = s4_data->pt_length - 45;
    for(; bytes_to_skip > 0; --bytes_to_skip)
    {
        fgetc(source);
    }
}

int s4_read(FILE *source, s4_type *s4_data)
{
    uint16_t type = 0;
    uint8_t is_binary = 0;
    uint16_t length = 0;
    
    if(source == NULL) return 1;
    
    memset(s4_data, 0, sizeof(s4_type));
    
    if(read_header(source, &type, &is_binary, &length)) return 1;
    
    if(type != 1 && type != 2) return 1;
    if(type == 1 && length < 157) return 1; // type1 requires min 157 bytes
    
    s4_data->type = type;
    
    if(type == 1)
    {
        s4_data->length = length;
        if(get_s4_bytes((uint8_t*)&s4_data->pt_length, source, 2, is_binary)) return 1;
        if(get_s4_bytes(s4_data->aes_gcm_iv, source, 12, is_binary)) return 1;
        if(get_s4_bytes(s4_data->scrypt_salt, source, 16, is_binary)) return 1;
        if(get_s4_bytes(&s4_data->scrypt_n_factor, source, 1, is_binary)) return 1;
        if(get_s4_bytes((uint8_t*)&s4_data->scrypt_iteration_count, source, 4, is_binary)) return 1;
        if(get_s4_bytes((uint8_t*)&s4_data->flags, source, 2, is_binary)) return 1;
        if(get_s4_bytes(&s4_data->hint_length, source, 1, is_binary)) return 1;
        if(get_s4_bytes(&s4_data->pw_verify_sec, source, 1, is_binary)) return 1;
        if(get_s4_bytes((uint8_t*)&s4_data->idle_timeout_min, source, 2, is_binary)) return 1;
        skip_unsupported_section(source, s4_data);
        if(get_s4_bytes(s4_data->enc_identity_master, source, 32, is_binary)) return 1;
        if(get_s4_bytes(s4_data->enc_identity_lock, source, 32, is_binary)) return 1;
        if(get_s4_bytes(s4_data->enc_prev_identity_unlock, source, 32, is_binary)) return 1;
        if(get_s4_bytes(s4_data->aes_gcm_verification, source, 16, is_binary)) return 1;
        // begin Type2
        if(get_s4_bytes((uint8_t*)&length, source, 2, is_binary)) return 1;
        if(get_s4_bytes((uint8_t*)&type, source, 2, is_binary)) return 1;
    }
    // Type2
    if(type == 2 && length != 73) return 1; // type2 73 bytes only
    s4_data->type2_length = length;
    if(get_s4_bytes(s4_data->type2_scrypt_salt, source, 16, is_binary)) return 1;
    if(get_s4_bytes(&s4_data->type2_scrypt_n_factor, source, 1, is_binary)) return 1;
    if(get_s4_bytes((uint8_t*)&s4_data->type2_scrypt_iteration_count, source, 4, is_binary)) return 1;
    if(get_s4_bytes(s4_data->type2_enc_identity_unlock, source, 32, is_binary)) return 1;
    if(get_s4_bytes(s4_data->type2_aes_gcm_verification, source, 16, is_binary)) return 1;
    
    return 0;
}

void log_option_flags(FILE *stm, s4_type *s4)
{
    fprintf(stm, "Options: ");
    if(s4->flags & e_s4_check_for_updates) fprintf(stm, "[update] ");
    if(s4->flags & e_s4_always_ask_identity) fprintf(stm, "[identity prompt] ");
    if(s4->flags & e_s4_sqrl_only) fprintf(stm, "[sqrlonly] ");
    if(s4->flags & e_s4_hard_lock) fprintf(stm, "[hardlock] ");
    if(s4->flags & e_s4_warn_mitm) fprintf(stm, "[mitm warn] ");
    if(s4->flags & e_s4_discard_on_suspend) fprintf(stm, "[discard on susp] ");
    if(s4->flags & e_s4_discard_on_switch) fprintf(stm, "[discard on switch] ");
    if(s4->flags & e_s4_discard_on_idle) fprintf(stm, "[discard on idle] ");
    fprintf(stm, "\n");
}

void s4_log(FILE *stm, s4_type *data)
{
    if(stm == NULL) return;
    if(data->type == 1)
    {
        fprintf(stm, "S4 Type1");
        fprintf(stm, "\nPT Length: %u", data->pt_length);
        fprintf(stm, "\nAES-GCM Init Vector: ");
        print_buffer_as_hex(stm, data->aes_gcm_iv, sizeof(data->aes_gcm_iv));
        fprintf(stm, "\nScrypt Random Salt: ");
        print_buffer_as_hex(stm, data->scrypt_salt, sizeof(data->scrypt_salt));
        fprintf(stm, "\nScrypt log(n-factor): %u", data->scrypt_n_factor);
        fprintf(stm, "\nScrypt iteration count: %u\n", data->scrypt_iteration_count);
        log_option_flags(stm, data);
        fprintf(stm, "Hint length: %u", data->hint_length);
        fprintf(stm, "\nPW Verify (sec): %u", data->pw_verify_sec);
        fprintf(stm, "\nIdle timeout (min): %u", data->idle_timeout_min);
        fprintf(stm, "\nIdentity master: ");
        print_buffer_as_hex(stm, data->enc_identity_master, sizeof(data->enc_identity_master));
        fprintf(stm, "\nIdentity lock: ");
        print_buffer_as_hex(stm, data->enc_identity_lock, sizeof(data->enc_identity_lock));
        fprintf(stm, "\nPrev. identity unlock: ");
        print_buffer_as_hex(stm, data->enc_prev_identity_unlock, sizeof(data->enc_prev_identity_unlock));
        fprintf(stm, "\nVerification tag: ");
        print_buffer_as_hex(stm, data->aes_gcm_verification, sizeof(data->aes_gcm_verification));
        fprintf(stm, "\n");
    }
    
    fprintf(stm, "S4 Type2");
    fprintf(stm, "\nScrypt Random Salt: ");
    print_buffer_as_hex(stm, data->type2_scrypt_salt, sizeof(data->type2_scrypt_salt));
    fprintf(stm, "\nScrypt log(n-factor): %u", data->type2_scrypt_n_factor);
    fprintf(stm, "\nScrypt iteration count: %u", data->type2_scrypt_iteration_count);
    fprintf(stm, "\nIdentity unlock key: ");
    print_buffer_as_hex(stm, data->type2_enc_identity_unlock, sizeof(data->type2_enc_identity_unlock));
    fprintf(stm, "\nVerification tag: ");
    print_buffer_as_hex(stm, data->type2_aes_gcm_verification, sizeof(data->type2_aes_gcm_verification));
    fprintf(stm, "\n");
}

#define WRITE(str, stm) if(fputs(str, stm) == EOF) return 1
#define WRITE_BYTES(stm, buf, buf_sz) if(write_bytes(stm, buf, buf_sz)) return 1

int write_s4_bytes(FILE *stm, uint8_t *buf, size_t count)
{
    return fwrite(buf, 1, count, stm) == count ? 0 : 1;
}

int write_type1_type(FILE *stm)
{
    if(fputc(1, stm) == EOF) return 1;
    if(fputc(0, stm) == EOF) return 1;
    return 0;
}

int write_type2_type(FILE *stm)
{
    if(fputc(2, stm) == EOF) return 1;
    if(fputc(0, stm) == EOF) return 1;
    return 0;
}

int s4_write(FILE *stm, s4_type *s4_data)
{
    if(!stm || !s4_data) return 1;
    if(s4_data->type != 1 && s4_data->type != 2) return 1;
    
    WRITE("sqrldata", stm);

    if(s4_data->type == 1)
    {
        write_s4_bytes(stm, (uint8_t*)&s4_data->length, sizeof(s4_data->length));
        write_type1_type(stm);
        write_s4_bytes(stm, (uint8_t*)&s4_data->pt_length, sizeof(s4_data->pt_length));
        write_s4_bytes(stm, (uint8_t*)&s4_data->aes_gcm_iv, sizeof(s4_data->aes_gcm_iv));
        write_s4_bytes(stm, (uint8_t*)&s4_data->scrypt_salt, sizeof(s4_data->scrypt_salt));
        write_s4_bytes(stm, (uint8_t*)&s4_data->scrypt_n_factor, sizeof(s4_data->scrypt_n_factor));
        write_s4_bytes(stm, (uint8_t*)&s4_data->scrypt_iteration_count, sizeof(s4_data->scrypt_iteration_count));
        write_s4_bytes(stm, (uint8_t*)&s4_data->flags, sizeof(s4_data->flags));
        write_s4_bytes(stm, (uint8_t*)&s4_data->hint_length, sizeof(s4_data->hint_length));
        write_s4_bytes(stm, (uint8_t*)&s4_data->pw_verify_sec, sizeof(s4_data->pw_verify_sec));
        write_s4_bytes(stm, (uint8_t*)&s4_data->idle_timeout_min, sizeof(s4_data->idle_timeout_min));
        write_s4_bytes(stm, (uint8_t*)&s4_data->enc_identity_master, sizeof(s4_data->enc_identity_master));
        write_s4_bytes(stm, (uint8_t*)&s4_data->enc_identity_lock, sizeof(s4_data->enc_identity_lock));
        write_s4_bytes(stm, (uint8_t*)&s4_data->enc_prev_identity_unlock, sizeof(s4_data->enc_prev_identity_unlock));
        write_s4_bytes(stm, (uint8_t*)&s4_data->aes_gcm_verification, sizeof(s4_data->aes_gcm_verification));
    }
    write_s4_bytes(stm, (uint8_t*)&s4_data->type2_length, sizeof(s4_data->type2_length));
    write_type2_type(stm);
    write_s4_bytes(stm, (uint8_t*)&s4_data->type2_scrypt_salt, sizeof(s4_data->type2_scrypt_salt));
    write_s4_bytes(stm, (uint8_t*)&s4_data->type2_scrypt_n_factor, sizeof(s4_data->type2_scrypt_n_factor));
    write_s4_bytes(stm, (uint8_t*)&s4_data->type2_scrypt_iteration_count, sizeof(s4_data->type2_scrypt_iteration_count));
    write_s4_bytes(stm, (uint8_t*)&s4_data->type2_enc_identity_unlock, sizeof(s4_data->type2_enc_identity_unlock));
    write_s4_bytes(stm, (uint8_t*)&s4_data->type2_aes_gcm_verification, sizeof(s4_data->type2_aes_gcm_verification));

    return 0;
}

void s4_create(s4_type **data)
{
    *data = malloc(sizeof(s4_type));
    if(*data)
    {
        s4_init(*data);
    }
}

void s4_init(s4_type *data)
{
    memset(data, 0, sizeof(s4_type));
    data->length = 157;
    data->type = 1;
    data->pt_length = 45;
    data->flags = e_s4_check_for_updates | e_s4_warn_mitm | e_s4_discard_on_suspend | e_s4_discard_on_switch | e_s4_discard_on_idle;
    data->hint_length = 4;
    data->pw_verify_sec = 5;
    data->idle_timeout_min = 15;
    data->type2_length = 73;
}

void s4_destroy(s4_type *data)
{
    free(data);
}

void s4_set_flag(s4_type *data, enum s4_flag flag)
{
    data->flags |= flag;
}

void s4_get_aad(s4_type *data, uint8_t *ptr_aad)
{
    if(data->type != 1) return;
    
    // fill in aad data
    memcpy(ptr_aad, &data->length, sizeof(data->length));
    ptr_aad += sizeof(data->length);
    memcpy(ptr_aad, &data->type, sizeof(data->type));
    ptr_aad += sizeof(data->type);
    memcpy(ptr_aad, &data->pt_length, sizeof(data->pt_length));
    ptr_aad += sizeof(data->pt_length);
    memcpy(ptr_aad, &data->aes_gcm_iv, sizeof(data->aes_gcm_iv));
    ptr_aad += sizeof(data->aes_gcm_iv);
    memcpy(ptr_aad, &data->scrypt_salt, sizeof(data->scrypt_salt));
    ptr_aad += sizeof(data->scrypt_salt);
    memcpy(ptr_aad, &data->scrypt_n_factor, sizeof(data->scrypt_n_factor));
    ptr_aad += sizeof(data->scrypt_n_factor);
    memcpy(ptr_aad, &data->scrypt_iteration_count, sizeof(data->scrypt_iteration_count));
    ptr_aad += sizeof(data->scrypt_iteration_count);
    memcpy(ptr_aad, &data->flags, sizeof(data->flags));
    ptr_aad += sizeof(data->flags);
    memcpy(ptr_aad, &data->hint_length, sizeof(data->hint_length));
    ptr_aad += sizeof(data->hint_length);
    memcpy(ptr_aad, &data->pw_verify_sec, sizeof(data->pw_verify_sec));
    ptr_aad += sizeof(data->pw_verify_sec);
    memcpy(ptr_aad, &data->idle_timeout_min, sizeof(data->idle_timeout_min));
}
