#include <string.h>
#include <stdio.h>
#include <locale.h>
#include "minunit.h"
#include <api.h>
#include <crypto.h>
#include <sodium.h>
#include <utils.h>
#include <base64.h>
#include <impl.h>
#include <strbuf.h>
#include <dict.h>

char* all_tests();
char* identity_tests();
char* enscrypt_tests();
char* aesgcm_tests();
char* ids_tests();
char* strbuf_tests();
char* dict_tests();
int aesGcmStartTest(const char* vf); // see gcmtest.c

int tests_run = 0;

int main(int argc, char *argv[])
{
    crypto_t *crypto = 0;
    crypto_init(&crypto);
    
    char *result = all_tests();
    if (result != 0) {
        printf("%s\n", result);
    }
    else {
        printf("ALL TESTS PASSED\n");
    }
    printf("Tests run: %d\n", tests_run);
    
    return result != 0;
}

char* all_tests()
{
    mu_run_test(dict_tests);
    mu_run_test(strbuf_tests);
    mu_run_test(ids_tests);
    mu_run_test(enscrypt_tests);
    mu_run_test(aesgcm_tests);
    mu_run_test(identity_tests);
    return 0;
}

unsigned int toInt(char c)
{
    if (c >= '0' && c <= '9') return      c - '0';
    if (c >= 'A' && c <= 'F') return 10 + c - 'A';
    if (c >= 'a' && c <= 'f') return 10 + c - 'a';
    return -1;
}

void convert_hex_to_bin(char *buf, size_t len)
{
    for(size_t r = 0, w = 0; r < len; ++w, r += 2)
    {
        buf[w] = 16 * toInt(buf[r]) + toInt(buf[r+1]);
    }
}

int enscryptTestStart()
{
    crypto_t *crypto = 0;
    crypto_init(&crypto);
    
    int ret = 0;
    const size_t buf_sz = 1024;
    char buf[buf_sz];
    char expected_hex[64]; // 32bytes, 64 hex
    char salt_hex[64]; // 16bytes, 32 hex characters
    char password[64]; // max 64 character password
    uint8_t salt_bin[32];
    uint8_t expected_bin[32];
    int iterations = 0;
    char out[32];
    size_t salt_len = 0;
    
    char *pswd, *psalt;
    FILE *fp = fopen("../../../test/data/enscrypt.txt", "r");
    if (!fp){
        printf("Failed to find test file\n");
        return 1;
    }
    memset(buf,0,buf_sz);
    while (fgets(buf, buf_sz, fp))
    {
        if(buf[0] == '#') continue;
        printf("%s\n", buf);
        memset(password, 0, sizeof(password));
        memset(salt_hex, 0, sizeof(salt_hex));
        memset(salt_bin, 0, sizeof(salt_bin));
        memset(expected_hex, 0, sizeof(expected_hex));
        memset(expected_bin, 0, sizeof(expected_bin));
        sscanf(buf, "%s%s%d%s", password, salt_hex, &iterations, expected_hex);
        pswd = psalt = 0;
        if(password[0] != '-')
        {
            pswd = password;
        }
        if(salt_hex[0] != '-')
        {
            salt_len = strnlen(salt_hex, sizeof(salt_hex));
            psalt = salt_hex;
            sodium_hex2bin(salt_bin, 32, psalt, salt_len, 0, &salt_len, 0);
            psalt = (char*)salt_bin;
        }
        sodium_hex2bin(expected_bin, 32, expected_hex, 64, 0, 0, 0);
        ret += enscrypt((const uint8_t*)pswd, (const uint8_t*)psalt, salt_len, 9, iterations, (uint8_t*)out);
        int enscrypt_result = memcmp(expected_bin, out, 32) == 0 ? 0 : 1;
        if(enscrypt_result)
        {
            printf("Error: %s\n", (const char*)buf);
        }
        ret += enscrypt_result;
    }
    crypto_free(crypto);
    return ret;
}

int test_identity_create()
{
    int ret = 1;
    sqrl_t *sqrl = 0;
    
    ret = sqrl_init(&sqrl);
    ret = sqrl_identity_create(sqrl);
    sqrl_destroy(sqrl);
    
    return ret;
}

int test_identity_save()
{
    int ret = 1;
    sqrl_t *sqrl = 0;
    
    sqrl_init(&sqrl);
    ret = sqrl_identity_create(sqrl);
    if(!ret)
    {
        FILE *fp = fopen("test_save.sqrl", "wb");
        ret = sqrl_identity_save(sqrl, fp);
        fclose(fp);
    }
    sqrl_destroy(sqrl);
    
    return ret;
}

int test_identity_save_then_load()
{
    int ret = 1;
    sqrl_t *sqrl = 0;
    
    sqrl_init(&sqrl);
    ret = sqrl_identity_create(sqrl);
    if(!ret)
    {
        FILE *fp = fopen("test_save_temp.sqrl", "wb");
        ret = sqrl_identity_save(sqrl, fp);
        fclose(fp);
    }
    if(!ret)
    {
        FILE *fp = fopen("test_save_temp.sqrl", "rb");
        ret = sqrl_identity_load(sqrl, fp, 0);
        fclose(fp);
    }
    sqrl_destroy(sqrl);
    
    return ret;
}

int test_identity_load()
{
    int ret = 1;
    sqrl_t *sqrl = 0;
    
    sqrl_init(&sqrl);
    FILE *fp = fopen("../../../test/data/test_load.sqrl", "rb");
    ret = sqrl_identity_load(sqrl, fp, 0);
    fclose(fp);    
    sqrl_destroy(sqrl);
    
    return ret;
}

int test_ids_val(sqrl_strbuf_t *buf_to_sign, sqrl_buffer_t *site_private_key, const char *expected)
{
    sqrl_strbuf_t base64_ids = SQRL_STRBUF_INIT;
    sqrl_buffer_t ids = SQRL_BUFFER_INIT;
    sqrl_buffer_create(&ids, 64);
    crypto_signature(ids.ptr, ids.len, (const uint8_t*)buf_to_sign->str, buf_to_sign->len, site_private_key->ptr, site_private_key->len);
    sqrl_base64(&base64_ids, ids.ptr, ids.len);
    //printf("ids=%s\n", base64_ids.str);
    if(strcmp(base64_ids.str, expected) != 0)
    {
        printf("ERROR\n");
        printf("Expected: %s\n", expected);
        printf("Instead : %s\n", base64_ids.str);
        return 1;
    }
    return 0;
}

int test_ids_val2(const char* buf_2_sign, const char *hex_private_key, const char *expected)
{
    size_t bin_len = 0;
    sqrl_strbuf_t buf_to_sign = SQRL_STRBUF_INIT;
    sqrl_buffer_t private_key_buf = SQRL_BUFFER_INIT;
    sqrl_strbuf_append_from_cstr(&buf_to_sign, buf_2_sign);
    sqrl_buffer_create(&private_key_buf, 64);
    sodium_hex2bin(private_key_buf.ptr, private_key_buf.len, hex_private_key, strnlen(hex_private_key, 1024), 0, &bin_len, 0);
    return test_ids_val(&buf_to_sign, &private_key_buf, expected);
}



int test_ids()
{
    int res = 0;
    res += test_ids_val2(
                         "dmVyPTENCmNtZD1xdWVyeQ0KaWRrPUlwV0xlN052bGpPX1drUTNta2RITGVWMU44NzBCOGV4cDkzb1BGNVR6c2sNCgc3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PXRDUnZhRlF3cVNONFVzeW5TT0J4N0Emc2ZuPVIxSkQ",
                         "E55B1D682E2C689880DDDB47F4E0D00A97B18F686F37BFBB7BAB99D6E6E3D72A22958B7BB36F9633BF5A44379A47472DE57537CEF407C7B1A7DDE83C5E53CEC9",
                         "5CIlEa-VLxlF9n0ZJ-RSCoKtcujKSRX0xnrgWxo5rM5QJvcMEVpkiivm5jFoe0OCsVWO9j8aGJX24kqgd2AbDA");
    res += test_ids_val2(
                         "dmVyPTENCmNtZD1xdWVyeQ0KaWRrPVBTZWhkdFRWdHY2S1JkQlpfMFZMTzZBTW01M0ZvbHd3OURXRllULWpUOFENCgc3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PW53a1RDUGNuWUg1SGVyMG5xdmFzRXcmc2ZuPVIxSkQ",
                         "8AE3882DA3E4932B2395EB89B2463DC84045ACA0C950F3B25069AA76586BCD3D3D27A176D4D5B6FE8A45D059FF454B3BA00C9B9DC5A25C30F43585613FA34FC4",
                         "xSkkqRxP3DP5pAH1hpne-OWfz2KXtmvcYJ6T82tdj11kituDnkqjqWtvl2LhprGa7TaZPGzWGXVuDfcOF7vfAg");
    res += test_ids_val2(
                         "dmVyPTENCmNtZD1pZGVudA0KaWRrPVBTZWhkdFRWdHY2S1JkQlpfMFZMTzZBTW01M0ZvbHd3OURXRllULWpUOFENCgdmVyPTENCm51dD1tbmllcDVlNzNDWGJHaW83bjBkWWh3DQp0aWY9NQ0KcXJ5PS9zcXJsP251dD1tbmllcDVlNzNDWGJHaW83bjBkWWh3DQpzZm49R1JDDQpzdWs9RkpVbS1mR29wdjIzNS1sYzNYZHBSalNxamhaUFRTSFVOOXhEc0htMEh3bw0K",
                         "8AE3882DA3E4932B2395EB89B2463DC84045ACA0C950F3B25069AA76586BCD3D3D27A176D4D5B6FE8A45D059FF454B3BA00C9B9DC5A25C30F43585613FA34FC4",
                         "qCImWx8_l8ZbGlHr2AeVpqb83wi1bQjLB-YhDfHvDHrS6ceSf_pZf1US8-vog02xK5W_beT7KFF9C5DZtmlOBA");
    
    return res;
    /*
    
    size_t bin_len = 0;
    char *buf_to_sign = "dmVyPTENCmNtZD1xdWVyeQ0KaWRrPUlwV0xlN052bGpPX1drUTNta2RITGVWMU44NzBCOGV4cDkzb1BGNVR6c2sNCgc3FybDovL3d3dy5ncmMuY29tL3Nxcmw_bnV0PXRDUnZhRlF3cVNONFVzeW5TT0J4N0Emc2ZuPVIxSkQ";
    char *hex_private_key = "E55B1D682E2C689880DDDB47F4E0D00A97B18F686F37BFBB7BAB99D6E6E3D72A22958B7BB36F9633BF5A44379A47472DE57537CEF407C7B1A7DDE83C5E53CEC9";
    char *hex_public_key = "22958B7BB36F9633BF5A44379A47472DE57537CEF407C7B1A7DDE83C5E53CEC9";
    char *hex_hmac256_hash = "E55B1D682E2C689880DDDB47F4E0D00A97B18F686F37BFBB7BAB99D6E6E3D72A";
    sqrl_buffer_t private_key_buf = SQRL_BUFFER_INIT;
    sqrl_buffer_t hash_buf = SQRL_BUFFER_INIT;
    sqrl_buffer_t public_key_buf = SQRL_BUFFER_INIT;
    sqrl_buffer_t hmac256_hash_buf = SQRL_BUFFER_INIT;
    sqrl_strbuf_t base64_ids = SQRL_STRBUF_INIT;
    sqrl_strbuf_t base64_idk = SQRL_STRBUF_INIT;
    
    sqrl_buffer_create(&private_key_buf, 64);
    sqrl_buffer_create(&hash_buf, 64);
    int res = sodium_hex2bin(private_key_buf.ptr, private_key_buf.len, hex_private_key, strnlen(hex_private_key, 1024), 0, &bin_len, 0);
    
    res += crypto_sign_ed25519_detached(hash_buf.ptr, (unsigned long long*)&hash_buf.len, (uint8_t*)buf_to_sign, strnlen(buf_to_sign, 1024), private_key_buf.ptr);
    
    sqrl_base64(&base64_ids, hash_buf.ptr, hash_buf.len);
    printf("ids=%s\n", base64_ids.str);

    res = strncmp(base64_ids.str, "5CIlEa-VLxlF9n0ZJ-RSCoKtcujKSRX0xnrgWxo5rM5QJvcMEVpkiivm5jFoe0OCsVWO9j8aGJX24kqgd2AbDA", 64) == 0 ? 0 : 1;
    
    /// IDK
    sqrl_buffer_create(&public_key_buf, 32);
    sodium_hex2bin(public_key_buf.ptr, public_key_buf.len, hex_public_key, strlen(hex_public_key), 0, &bin_len, 0);
    sqrl_base64(&base64_idk, public_key_buf.ptr, public_key_buf.len);
    printf("idk=%s\n", base64_idk.str);
    
    // create IDK
    sqrl_buffer_create(&hmac256_hash_buf, 32);
    sodium_hex2bin(hmac256_hash_buf.ptr, hmac256_hash_buf.len, hex_hmac256_hash, strlen(hex_hmac256_hash), 0, &bin_len, 0);
    crypto_sign_ed25519_seed_keypair(public_key_buf.ptr, private_key_buf.ptr, hmac256_hash_buf.ptr);
    sqrl_base64(&base64_idk, public_key_buf.ptr, public_key_buf.len);
    printf("idk=%s\n", base64_idk.str);

    sqrl_buffer_free(&private_key_buf);
    sqrl_buffer_free(&hash_buf);

    return res;
     */
}

int test_strbuf()
{
    int res = 0;
    
    sqrl_strbuf_t strbuf0 = SQRL_STRBUF_INIT;
    sqrl_strbuf_t strbuf1 = SQRL_STRBUF_INIT;
    const char *str0 = "In a hole in the ground";
    const char *str1 = " there lived a hobbit.";
    
    sqrl_strbuf_create_from_string(&strbuf0, str0);
    res = strbuf0.len == strlen(str0) ? 0 : 1;
    sqrl_strbuf_create_from_string(&strbuf1, str1);
    sqrl_strbuf_append(&strbuf0, &strbuf1);
    printf("%s\n", strbuf0.str);
    res = strbuf0.len == strlen(str0) + strlen(str1) ? 0 : 1;
    sqrl_strbuf_release(&strbuf0);
    sqrl_strbuf_release(&strbuf1);
    
    return res;
}

int test_dict()
{
    int res = 0;
    int count = 0;
    
    sqrl_dict_t dict = SQRL_DICT_INIT;
    sqrl_dict_add(&dict, "my_key0", "my_value0");
    sqrl_dict_add(&dict, "my_key1", "my_value1");
    sqrl_dict_add(&dict, "my_key2", "my_value2");
    res += (sqrl_dict_has(&dict, "my_key1") != 0) ? 0 : 1;
    res += (sqrl_dict_has(&dict, "bad key") != 0) ? 1 : 0;
    
    for(sqrl_dict_begin(&dict); !sqrl_dict_is_done(&dict); sqrl_dict_next(&dict))
    {
        printf("%s:%s\n", sqrl_dict_current_key(&dict), sqrl_dict_current_value(&dict));
        ++count;
    }
    res += count == 3 ? 0 : 1;
    
    sqrl_dict_free(&dict);
    
    return res;
}

char* identity_tests()
{
    printf("Identity Test\n");
    mu_assert("[FAIL] Create Identity", test_identity_create() == 0);
    mu_assert("[FAIL] Save Identity", test_identity_save() == 0);
    mu_assert("[FAIL] Save Identity", test_identity_save_then_load() == 0);
    mu_assert("[FAIL] Load Identity", test_identity_load() == 0);
    printf("[PASS] Identity\n");
    return 0;
}

char* enscrypt_tests()
{
    printf("EnScrypt Test\n");
    mu_assert("[FAIL] EnScrypt", enscryptTestStart() == 0);
    printf("[PASS] EnScrypt\n");
    return 0;
}

char* aesgcm_tests()
{
    printf("AES-GCM Test\n");
    mu_assert("[FAIL] AES-GCM", aesGcmStartTest("../../../test/data/gcm_test_vectors.bin") == 0);
    printf("[PASS] AES-GCM\n");
    return 0;
}

char* dict_tests()
{
    printf("Dict Test\n");
    mu_assert("[FAIL] Dict", test_dict() == 0);
    printf("[PASS] Dict\n");
    return 0;
}

char* ids_tests()
{
    printf("IDS Test\n");
    mu_assert("[FAIL] IDS", test_ids() == 0);
    printf("[PASS] IDS\n");
    return 0;
}

char* strbuf_tests()
{
    printf("strbuf Test\n");
    mu_assert("[FAIL] strbuf", test_strbuf() == 0);
    printf("[PASS] strbuf\n");
    return 0;
}
