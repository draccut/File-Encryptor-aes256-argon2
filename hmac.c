#include "hmac.h"

#include "sha256.h"
#include "argon2.h"

#include <string.h>

#define SHA256_BLOCK_SIZE 32
#define SHA256_INTERNAL_BLOCK_SIZE 64

void compute_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t *hmac_out)
{
    SHA256_CTX ctx;
    uint8_t k_ipad[SHA256_INTERNAL_BLOCK_SIZE];
    uint8_t k_opad[SHA256_INTERNAL_BLOCK_SIZE];
    uint8_t hashed_key[SHA256_BLOCK_SIZE];
    if (key_len > SHA256_INTERNAL_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, hashed_key);
        key = hashed_key;
        key_len = SHA256_BLOCK_SIZE;
    }
    memset(k_ipad, 0, SHA256_INTERNAL_BLOCK_SIZE);
    memset(k_opad, 0, SHA256_INTERNAL_BLOCK_SIZE);
    memcpy(k_ipad, key, key_len);
    memcpy(k_opad, key, key_len);
    for (int i = 0; i < SHA256_INTERNAL_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }
    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_INTERNAL_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, hmac_out);
    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_INTERNAL_BLOCK_SIZE);
    sha256_update(&ctx, hmac_out, SHA256_BLOCK_SIZE);
    sha256_final(&ctx, hmac_out);
}

int derive_keys_64b(const char *password, size_t pwd_len, const uint8_t *salt, uint8_t *master_key_out)
{
    return argon2id_hash_raw(3, 65536, 1, password, pwd_len, salt, 16, master_key_out, 64);
}
