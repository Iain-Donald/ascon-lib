/*
// ascon_xof.c
Ascon-XOF128 and Ascon-CXOF128 // NIST SP 800-232, section 5.2-5.4.

The two functions share a mode of operation and differ only in their initial value and, for CXOF128, a customization string absorbed before the message.

The incremental API follows the restrictions in Sec. 5.4: absorbing may not continue once squeezing has begun, and the first squeeze is what pads and absorbs the final message block.
*/

#include "ascon.h"
#include "ascon_perm.h"
#include "ascon_sponge.h"
#include "ascon_word.h"

// shared internals //
static void xof_reset(ascon_xof128_ctx *ctx, uint64_t iv) {
  ascon_sponge_init(&ctx->s, iv);
  ctx->buf_len = 0;
  ctx->squeeze_i = 0;
  ctx->squeezing = 0;
}

static void xof_squeeze(ascon_xof128_ctx *ctx, uint8_t *out, size_t out_len) {
  size_t i;
  // The first squeeze is what pads and absorbs the final block.
  if (!ctx->squeezing) {
    ascon_sponge_finish(&ctx->s, ctx->buf, &ctx->buf_len);
    ctx->squeeze_i = 0;
    ctx->squeezing = 1;
  }

  for (i = 0; i < out_len; i++) {
    // Permute lazily. The final block is never followed by a permutation the caller did not ask for.
    if (ctx->squeeze_i == ASCON_HASH_RATE) {
      ascon_permute(&ctx->s, 12);
      ctx->squeeze_i = 0;
    }
    out[i] = (uint8_t)(ctx->s.x[0] >> (8 * ctx->squeeze_i));
    ctx->squeeze_i++;
  }
}

// Ascon-XOF128 //
void ascon_xof128_init(ascon_xof128_ctx *ctx) {
  xof_reset(ctx, ASCON_XOF128_IV);
}

void ascon_xof128_update(ascon_xof128_ctx *ctx, const uint8_t *in, size_t in_len) {
  ascon_sponge_absorb(&ctx->s, ctx->buf, &ctx->buf_len, in, in_len);
}

void ascon_xof128_squeeze(ascon_xof128_ctx *ctx, uint8_t *out, size_t out_len) {
  xof_squeeze(ctx, out, out_len);
}

void ascon_xof128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len) {
  ascon_xof128_ctx ctx;
  ascon_xof128_init(&ctx);
  ascon_xof128_update(&ctx, in, in_len);
  ascon_xof128_squeeze(&ctx, out, out_len);
}

// Ascon-CXOF128 //
int ascon_cxof128_init(ascon_cxof128_ctx *ctx, const uint8_t *cs, size_t cs_len) {
  uint8_t len_block[ASCON_HASH_RATE];

  // SP 800-232 section 5.3: the customization string must be at most 2048 bits.
  if (cs_len > ASCON_CXOF128_MAX_CS_SIZE) {
    return ASCON_ERR_PARAMETER;
  }

  xof_reset(ctx, ASCON_CXOF128_IV);

  // Z0 is the bit length of the customization string as a 64-bit little-endian block, absorbed before the string itself.
  ascon_store_bytes(len_block, (uint64_t)cs_len * 8, ASCON_HASH_RATE);
  ascon_sponge_block(&ctx->s, len_block);

  // The customization string is absorbed and padded as its own phase, so the message absorb that follows starts on a block boundary.
  ascon_sponge_absorb(&ctx->s, ctx->buf, &ctx->buf_len, cs, cs_len);
  ascon_sponge_finish(&ctx->s, ctx->buf, &ctx->buf_len);

  return ASCON_OK;
}

void ascon_cxof128_update(ascon_cxof128_ctx *ctx, const uint8_t *in, size_t in_len) {
  ascon_sponge_absorb(&ctx->s, ctx->buf, &ctx->buf_len, in, in_len);
}

void ascon_cxof128_squeeze(ascon_cxof128_ctx *ctx, uint8_t *out, size_t out_len) {
  xof_squeeze(ctx, out, out_len);
}

int ascon_cxof128(uint8_t *out, size_t out_len, const uint8_t *in, size_t in_len, const uint8_t *cs, size_t cs_len) {
  ascon_cxof128_ctx ctx;
  int rc = ascon_cxof128_init(&ctx, cs, cs_len);
  if (rc != ASCON_OK) {
    return rc;
  }
  ascon_cxof128_update(&ctx, in, in_len);
  ascon_cxof128_squeeze(&ctx, out, out_len);
  return ASCON_OK;
}
