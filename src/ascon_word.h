/*
// ascon_word.h
conversion between byte sequences and 64-bit state words

SP 800-232 uses little-endian ordering, the first byte of a sequence is the least significant byte of the word. These functions build words a byte at a time and behave identically on little endian and big endian machines.
*/

#ifndef ASCON_WORD_H
#define ASCON_WORD_H

#include <stddef.h>
#include <stdint.h>

// Domain separation bit, SP 800-232 section A.2: the bit added to S4.
#define ASCON_DSEP 0x8000000000000000ULL

// Load n bytes (0 <= n <= 8) as the low bytes of a 64-bit word.
static inline uint64_t ascon_load_bytes(const uint8_t *in, size_t n) {
  uint64_t x = 0;
  size_t i;
  for (i = 0; i < n; i++)
    x |= (uint64_t)in[i] << (8 * i);
  return x;
}

// Store the low n bytes (0 <= n <= 8) of a word as a byte sequence.
static inline void ascon_store_bytes(uint8_t *out, uint64_t x, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    out[i] = (uint8_t)(x >> (8 * i));
}

// The padding bit for a partial block of n bytes (0 <= n <= 7): a single 1 bit immediately after the data. SP 800-232 section A.2.
static inline uint64_t ascon_pad(size_t n) { return 1ULL << (8 * n); }

// XOR the low n bytes of a word into a byte sequence (0 <= n <= 8). Used to produce keystream-XORed ciphertext and plaintext.
static inline void ascon_xor_bytes(uint8_t *out, const uint8_t *in, uint64_t x, size_t n) {
  size_t i;
  for (i = 0; i < n; i++)
    out[i] = in[i] ^ (uint8_t)(x >> (8 * i));
}
#endif
