/*
 * ad_crypt.h - Crypto abstraction for ad_vpn
 *
 * Opinionated, minimal, and safe-by-default.
 */

#ifndef AD_CRYPT_H
#define AD_CRYPT_H

#include <stddef.h>
#include <stdint.h>
#include "../../../prebuilt/libsodium/include/sodium.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ---- Cipher Selection ---- */
typedef enum {
    AD_CRYPT_CIPHER_CHACHA20_POLY1305 = 1
} ad_crypt_cipher_t;

/* ---- Opaque Context ---- */
typedef struct ad_crypt_ctx ad_crypt_ctx_t;

/* ---- API ---- */
int ad_crypt_ctx_create(
    ad_crypt_ctx_t **ctx,
    ad_crypt_cipher_t cipher,
    const uint8_t *key,
    size_t key_len
);

int ad_crypt_encrypt(
    ad_crypt_ctx_t *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out,
    size_t *out_len
);

int ad_crypt_decrypt(
    ad_crypt_ctx_t *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out,
    size_t *out_len
);

int ad_crypt_rekey(
    ad_crypt_ctx_t *ctx,
    const uint8_t *new_key,
    size_t key_len
);

void ad_crypt_ctx_destroy(ad_crypt_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif /* AD_CRYPT_H */