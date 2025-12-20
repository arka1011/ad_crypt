#include "../../../prebuilt/googletest/googletest/include/gtest/gtest.h"
#include "../../../prebuilt/libsodium/include/sodium.h"
#include <errno.h>
#include <string.h>

extern "C" {
#include "../include/ad_crypt.h"
}

/* ------------------------------------------------------------
 * Context creation tests (no fixture)
 * ------------------------------------------------------------ */
TEST(AdCryptCreate, InvalidArguments)
{
    ad_crypt_ctx_t *ctx = nullptr;
    uint8_t key[16];

    EXPECT_EQ(
        ad_crypt_ctx_create(
            &ctx,
            AD_CRYPT_CIPHER_CHACHA20_POLY1305,
            key,
            sizeof(key)),
        -1
    );
    EXPECT_EQ(errno, EINVAL);
}

/* ------------------------------------------------------------
 * Test Fixture
 * ------------------------------------------------------------ */
class AdCryptTest : public ::testing::Test {
protected:
    ad_crypt_ctx_t *ctx{};
    uint8_t key[32];

    void SetUp() override {
        /* libsodium may return 0 (first init) or 1 (already init) */
        ASSERT_GE(sodium_init(), 0);

        randombytes_buf(key, sizeof(key));

        ASSERT_EQ(
            ad_crypt_ctx_create(
                &ctx,
                AD_CRYPT_CIPHER_CHACHA20_POLY1305,
                key,
                sizeof(key)),
            0
        );
    }

    void TearDown() override {
        ad_crypt_ctx_destroy(ctx);
    }
};

/* ------------------------------------------------------------
 * Encrypt / Decrypt happy path
 * ------------------------------------------------------------ */
TEST_F(AdCryptTest, EncryptDecryptRoundTrip)
{
    const uint8_t plaintext[] = "hello secure world";
    const uint8_t aad[] = "header-data";

    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;

    uint8_t decrypted[128];
    size_t decrypted_len = 0;

    ASSERT_EQ(
        ad_crypt_encrypt(
            ctx,
            plaintext,
            sizeof(plaintext),
            aad,
            sizeof(aad),
            ciphertext,
            &ciphertext_len),
        0
    );

    ASSERT_GT(ciphertext_len, sizeof(plaintext));

    ASSERT_EQ(
        ad_crypt_decrypt(
            ctx,
            ciphertext,
            ciphertext_len,
            aad,
            sizeof(aad),
            decrypted,
            &decrypted_len),
        0
    );

    ASSERT_EQ(decrypted_len, sizeof(plaintext));
    ASSERT_EQ(memcmp(decrypted, plaintext, sizeof(plaintext)), 0);
}

/* ------------------------------------------------------------
 * AAD mismatch must fail
 * ------------------------------------------------------------ */
TEST_F(AdCryptTest, AadMismatchFails)
{
    const uint8_t plaintext[] = "top secret";
    const uint8_t aad1[] = "aad-one";
    const uint8_t aad2[] = "aad-two";

    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;

    uint8_t decrypted[128];
    size_t decrypted_len = 0;

    ASSERT_EQ(
        ad_crypt_encrypt(
            ctx,
            plaintext,
            sizeof(plaintext),
            aad1,
            sizeof(aad1),
            ciphertext,
            &ciphertext_len),
        0
    );

    EXPECT_EQ(
        ad_crypt_decrypt(
            ctx,
            ciphertext,
            ciphertext_len,
            aad2,
            sizeof(aad2),
            decrypted,
            &decrypted_len),
        -1
    );
    EXPECT_EQ(errno, EBADMSG);
}

/* ------------------------------------------------------------
 * Replay protection
 * ------------------------------------------------------------ */
TEST_F(AdCryptTest, ReplayIsRejected)
{
    const uint8_t plaintext[] = "replay me if you can";
    const uint8_t aad[] = "aad";

    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;

    uint8_t decrypted[128];
    size_t decrypted_len = 0;

    ASSERT_EQ(
        ad_crypt_encrypt(
            ctx,
            plaintext,
            sizeof(plaintext),
            aad,
            sizeof(aad),
            ciphertext,
            &ciphertext_len),
        0
    );

    /* First decrypt succeeds */
    ASSERT_EQ(
        ad_crypt_decrypt(
            ctx,
            ciphertext,
            ciphertext_len,
            aad,
            sizeof(aad),
            decrypted,
            &decrypted_len),
        0
    );

    /* Replay must fail */
    EXPECT_EQ(
        ad_crypt_decrypt(
            ctx,
            ciphertext,
            ciphertext_len,
            aad,
            sizeof(aad),
            decrypted,
            &decrypted_len),
        -1
    );
    EXPECT_EQ(errno, EPROTO);
}

/* ------------------------------------------------------------
 * Ciphertext tampering
 * ------------------------------------------------------------ */
TEST_F(AdCryptTest, TamperedCiphertextFails)
{
    const uint8_t plaintext[] = "do not touch";
    const uint8_t aad[] = "aad";

    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;

    uint8_t decrypted[128];
    size_t decrypted_len = 0;

    ASSERT_EQ(
        ad_crypt_encrypt(
            ctx,
            plaintext,
            sizeof(plaintext),
            aad,
            sizeof(aad),
            ciphertext,
            &ciphertext_len),
        0
    );

    /* Flip a bit after nonce */
    ciphertext[12] ^= 0xFF;

    EXPECT_EQ(
        ad_crypt_decrypt(
            ctx,
            ciphertext,
            ciphertext_len,
            aad,
            sizeof(aad),
            decrypted,
            &decrypted_len),
        -1
    );
    EXPECT_EQ(errno, EBADMSG);
}

/* ------------------------------------------------------------
 * Rekey resets nonces and works
 * ------------------------------------------------------------ */
TEST_F(AdCryptTest, RekeyWorks)
{
    uint8_t new_key[32];
    randombytes_buf(new_key, sizeof(new_key));

    ASSERT_EQ(
        ad_crypt_rekey(ctx, new_key, sizeof(new_key)),
        0
    );

    const uint8_t plaintext[] = "post-rekey";
    const uint8_t aad[] = "aad";

    uint8_t ciphertext[128];
    size_t ciphertext_len = 0;

    uint8_t decrypted[128];
    size_t decrypted_len = 0;

    ASSERT_EQ(
        ad_crypt_encrypt(
            ctx,
            plaintext,
            sizeof(plaintext),
            aad,
            sizeof(aad),
            ciphertext,
            &ciphertext_len),
        0
    );

    ASSERT_EQ(
        ad_crypt_decrypt(
            ctx,
            ciphertext,
            ciphertext_len,
            aad,
            sizeof(aad),
            decrypted,
            &decrypted_len),
        0
    );

    ASSERT_EQ(decrypted_len, sizeof(plaintext));
    ASSERT_EQ(memcmp(decrypted, plaintext, sizeof(plaintext)), 0);
}
