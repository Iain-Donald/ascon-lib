/*
// ascon.h
Ascon lightweight cryptography - NIST SP 800-232.

Implements the four standardized functions
Ascon-AEAD128, Ascon-Hash256, Ascon-XOF128, Ascon-CXOF128.
 */

#ifndef ASCON_H
#define ASCON_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// sizes.
#define ASCON_HASH256_SIZE 32 // ascon-hash256 digest length.
#define ASCON_AEAD128_KEY_SIZE 16
#define ASCON_AEAD128_NONCE_SIZE 16
#define ASCON_AEAD128_TAG_SIZE 16

// longest customization string accepted by Ascon-CXOF128 (SP 800-232 caps this at 2048 bits).               
#define ASCON_CXOF128_MAX_CS_SIZE 256

// RCs
#define ASCON_OK 0
#define ASCON_ERR_TAG (-1) // authentication failed, output is unusable.
#define ASCON_ERR_PARAMETER (-2)

// incremental contexts
// The permutation state. Exposed so contexts can live on the stack, treat the contents as opaque.
typedef struct {
  uint64_t x[5];
} ascon_state;

// ascon-hash256
typedef struct {
  ascon_state s;
  uint8_t buf[8];
  size_t buf_len;
} ascon_hash256_ctx;

// Ascon-XOF128 and Ascon-CXOF128 share a context. CXOF differs only in its initial value and a customization string absorbed up front.
typedef struct {
  ascon_state s;
  uint8_t buf[8];
  size_t buf_len; // bytes buffered for absorbing.
  size_t squeeze_i; // byte offset in the current squeezed block.
  int squeezing; // nonzero once output has started.
} ascon_xof128_ctx;

typedef ascon_xof128_ctx ascon_cxof128_ctx;

/// Ascon-Hash256 ///
void ascon_hash256_init(ascon_hash256_ctx *ctx);
void ascon_hash256_update(ascon_hash256_ctx *ctx, const uint8_t *in, size_t in_len);
void ascon_hash256_final(ascon_hash256_ctx *ctx, uint8_t out[ASCON_HASH256_SIZE]);

void ascon_hash256(uint8_t out[ASCON_HASH256_SIZE], const uint8_t *in, size_t in_len);

/// Ascon-XOF128 ///
void ascon_xof128_init(ascon_xof128_ctx *ctx);
void ascon_xof128_update(ascon_xof128_ctx *ctx, const uint8_t *in, size_t in_len);

// May be called repeatedly. Output is the continuation of one stream.
void ascon_xof128_squeeze(ascon_xof128_ctx *ctx, uint8_t *out, size_t out_len);

void ascon_xof128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len);

/// Ascon-CXOF128 ///
// Returns ASCON_ERR_PARAM if cs_len exceeds ASCON_CXOF128_MAX_CS_SIZE.
int ascon_cxof128_init(ascon_cxof128_ctx *ctx, const uint8_t *cs, size_t cs_len);
void ascon_cxof128_update(ascon_cxof128_ctx *ctx, const uint8_t *in, size_t in_len);
void ascon_cxof128_squeeze(ascon_cxof128_ctx *ctx, uint8_t *out, size_t out_len);

int ascon_cxof128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len, const uint8_t *cs, size_t cs_len);

/// Ascon-AEAD128 /// 
// ct must have room for pt_len bytes. The tag is written separately.
void ascon_aead128_encrypt(uint8_t *ct, uint8_t tag[ASCON_AEAD128_TAG_SIZE],
                           const uint8_t *pt, size_t pt_len, const uint8_t *ad,
                           size_t ad_len,
                           const uint8_t key[ASCON_AEAD128_KEY_SIZE],
                           const uint8_t nonce[ASCON_AEAD128_NONCE_SIZE]);

// Returns ASCON_OK or ASCON_ERR_TAG. On failure pt is zeroed. 
int ascon_aead128_decrypt(uint8_t *pt, const uint8_t *ct, size_t ct_len,
                          const uint8_t tag[ASCON_AEAD128_TAG_SIZE],
                          const uint8_t *ad, size_t ad_len,
                          const uint8_t key[ASCON_AEAD128_KEY_SIZE],
                          const uint8_t nonce[ASCON_AEAD128_NONCE_SIZE]);

#ifdef __cplusplus
}
#endif

#endif // ASCON_H //
