/*
// ascon_sponge.h
Absorbing helpers shared by the hash and XOF modes.

Ascon-Hash256, Ascon-XOF128, and Ascon-CXOF128 absorb the message identically. A 64-bit rate, Ascon-p[12] after each block, and final partial block padded with a single 1 bit. Only the initial value and the output phase differ between them. 

These take the state and caller's partial-block buffer separately, so each mode can keep whatever context struct suits it.
*/

#ifndef ASCON_SPONGE_H
#define ASCON_SPONGE_H

#include "ascon_perm.h"
#include "ascon_word.h"

// Initialize the state to IV || 0^256 and apply Ascon-p[12].
static inline void ascon_sponge_init(ascon_state *s, uint64_t iv) {
  s->x[0] = iv;
  s->x[1] = 0;
  s->x[2] = 0;
  s->x[3] = 0;
  s->x[4] = 0;
  ascon_permute(s, 12);
}

// XOR a full 8-byte block into the rate and apply Ascon-p[12].
static inline void ascon_sponge_block(ascon_state *s, const uint8_t *block) {
  s->x[0] ^= ascon_load_bytes(block, ASCON_HASH_RATE);
  ascon_permute(s, 12);
}

// Absorb an arbitrary-length input, buffering any partial block. On return *buf_len is always in 0..7, never 8.
static inline void ascon_sponge_absorb(ascon_state *s, uint8_t *buf, size_t *buf_len, const uint8_t *in, size_t in_len) {
  size_t i;
  // Complete/fill a partially filled buffer first.
  while (*buf_len > 0 && in_len > 0) {
    buf[(*buf_len)++] = *in++;
    in_len--;
    if (*buf_len == ASCON_HASH_RATE) {
      ascon_sponge_block(s, buf);
      *buf_len = 0;
    }
  }

  // Absorb whole blocks straight from the input.
  while (in_len >= ASCON_HASH_RATE) {
    ascon_sponge_block(s, in);
    in += ASCON_HASH_RATE;
    in_len -= ASCON_HASH_RATE;
  }

  // What is left is a partial block.
  for (i = 0; i < in_len; i++) {
    buf[(*buf_len)++] = in[i];
  }
}

// Pad and absorb the buffered final block then permute. End of a hase!
static inline void ascon_sponge_finish(ascon_state *s, const uint8_t *buf, size_t *buf_len) {
  s->x[0] ^= ascon_load_bytes(buf, *buf_len);
  s->x[0] ^= ascon_pad(*buf_len);
  ascon_permute(s, 12);
  *buf_len = 0;
}
#endif
