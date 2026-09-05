/*
// ascon_hash.c
Ascon-Hash256 // SP 800-232, section 5.1.

Ascon-Hash256 uses the same sponge as the XOFs with a different initial value and a fixed 256-bit output.
*/

#include "ascon.h"
#include "ascon_perm.h"
#include "ascon_sponge.h"
#include "ascon_word.h"

void ascon_hash256_init(ascon_hash256_ctx *ctx) {
  ascon_sponge_init(&ctx->s, ASCON_HASH256_IV);
  ctx->buf_len = 0;
}

void ascon_hash256_update(ascon_hash256_ctx *ctx, const uint8_t *in, size_t in_len) {
  ascon_sponge_absorb(&ctx->s, ctx->buf, &ctx->buf_len, in, in_len);
}

void ascon_hash256_final(ascon_hash256_ctx *ctx, uint8_t out[ASCON_HASH256_SIZE]) {
  size_t i;
  ascon_sponge_finish(&ctx->s, ctx->buf, &ctx->buf_len);
  // Four 64-bit blocks. The last is extracted without a following permutation, so the permute goes at the top of the loop.
  for (i = 0; i < ASCON_HASH256_SIZE / ASCON_HASH_RATE; i++) {
    if (i > 0) {
      ascon_permute(&ctx->s, 12);
    }
    ascon_store_bytes(out + i * ASCON_HASH_RATE, ctx->s.x[0], ASCON_HASH_RATE);
  }
}

void ascon_hash256(uint8_t out[ASCON_HASH256_SIZE], const uint8_t *in, size_t in_len) {
  ascon_hash256_ctx ctx;
  ascon_hash256_init(&ctx);
  ascon_hash256_update(&ctx, in, in_len);
  ascon_hash256_final(&ctx, out);
}
