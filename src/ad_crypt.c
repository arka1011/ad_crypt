/* ============================================================ */
/* ad_crypt.c - reference implementation using libsodium-style API */
/* ============================================================ */

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "../include/ad_crypt.h"

struct ad_crypt_ctx {

    ad_crypt_cipher_t cipher;
    uint8_t key[32];
    uint64_t send_nonce;
    uint64_t recv_nonce;
};

static void secure_zero(void *p, size_t n)
{
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

int ad_crypt_ctx_create(
    ad_crypt_ctx_t **ctx,
    ad_crypt_cipher_t cipher,
    const uint8_t *key,
    size_t key_len)
{
    if (!ctx || !key || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

    if (cipher != AD_CRYPT_CIPHER_CHACHA20_POLY1305) {
        errno = ENOTSUP;
        return -1;
    }

    ad_crypt_ctx_t *c = calloc(1, sizeof(*c));
    if (!c)
        return -1;

    c->cipher = cipher;
    memcpy(c->key, key, 32);
    c->send_nonce = 0;
    c->recv_nonce = 0;

    *ctx = c;
    return 0;
}

int ad_crypt_encrypt(
    ad_crypt_ctx_t *ctx,
    const uint8_t *plaintext,
    size_t plaintext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out,
    size_t *out_len)
{
    if (!ctx || !plaintext || !out || !out_len) {
        errno = EINVAL;
        return -1;
    }

    /* Layout: [8-byte nonce | ciphertext | 16-byte tag] */
    uint64_t nonce = ctx->send_nonce++;
    memcpy(out, &nonce, sizeof(nonce));

    unsigned long long clen = 0;
    uint8_t nonce_bytes[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = {0};
    memcpy(nonce_bytes + 4, &nonce, sizeof(nonce));

    crypto_aead_chacha20poly1305_ietf_encrypt(
        out + 8,
        &clen,
        plaintext,
        plaintext_len,
        aad,
        aad_len,
        NULL,
        nonce_bytes,
        ctx->key
    );

    *out_len = 8 + plaintext_len + 16;
    return 0;
}

int ad_crypt_decrypt(
    ad_crypt_ctx_t *ctx,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    const uint8_t *aad,
    size_t aad_len,
    uint8_t *out,
    size_t *out_len)
{
    if (!ctx || !ciphertext || ciphertext_len < 24 || !out || !out_len) {
        errno = EINVAL;
        return -1;
    }

    uint64_t nonce;
    memcpy(&nonce, ciphertext, sizeof(nonce));

    if (nonce < ctx->recv_nonce) {
        errno = EPROTO;
        return -1; /* replay */
    }
    ctx->recv_nonce = nonce + 1;

    size_t pt_len = ciphertext_len - 8 - 16;

    unsigned long long plen = 0;
    uint8_t nonce_bytes[crypto_aead_chacha20poly1305_ietf_NPUBBYTES] = {0};
    memcpy(nonce_bytes + 4, &nonce, sizeof(nonce));

    if (crypto_aead_chacha20poly1305_ietf_decrypt(
            out,
            &plen,
            NULL,
            ciphertext + 8,
            ciphertext_len - 8,
            aad,
            aad_len,
            nonce_bytes,
            ctx->key) != 0) {
        errno = EBADMSG;
        return -1;
    }

    *out_len = plen;
    return 0;
    memcpy(out, ciphertext + 8, pt_len);

    *out_len = pt_len;
    return 0;
}

int ad_crypt_rekey(
    ad_crypt_ctx_t *ctx,
    const uint8_t *new_key,
    size_t key_len)
{
    if (!ctx || !new_key || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

    secure_zero(ctx->key, sizeof(ctx->key));
    memcpy(ctx->key, new_key, 32);
    ctx->send_nonce = 0;
    ctx->recv_nonce = 0;

    return 0;
}

void ad_crypt_ctx_destroy(ad_crypt_ctx_t *ctx)
{
    if (!ctx)
        return;

    secure_zero(ctx, sizeof(*ctx));
    free(ctx);
}
