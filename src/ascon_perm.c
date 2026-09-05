/*
// ascon_perm.c
Ascon permutation // NIST SP 800-232, section 3

The permutation is the composition p(x) = pL(pS(pC(x))), applied <rounds> times to the 320-bit state as five 64 bit words.
*/
#include "ascon_perm.h"

// Round constants const_0 .. const_15, SP 800-232 table 5. 
static const uint8_t ascon_round_constants[16] = { 0x3c, 0x2d, 0x1e, 0x0f, 0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b };

// Right rotation of a 64-bit word. n must be in 1..63. 
static uint64_t rrot64(uint64_t x, int n) {
  return (x >> n) | (x << (64 - n));
}

void ascon_permute(ascon_state *state, int rounds) {
  uint64_t x0 = state->x[0];
  uint64_t x1 = state->x[1];
  uint64_t x2 = state->x[2];
  uint64_t x3 = state->x[3];
  uint64_t x4 = state->x[4];
  uint64_t t0, t1, t2, t3, t4;
  int i;
  for (i = 0; i < rounds; i++) {
    // pC: add the round constant to S2. Round i of an rnd-round permutation uses const[16 - rnd + i].
    x2 ^= (uint64_t)ascon_round_constants[16 - rounds + i];
    //pS: 64 parallel applications of the 5-bit S-box, computed bitsliced across the five words.
    x0 ^= x4;
    x4 ^= x3;
    x2 ^= x1;
    t0 = ~x0 & x1;
    t1 = ~x1 & x2;
    t2 = ~x2 & x3;
    t3 = ~x3 & x4;
    t4 = ~x4 & x0;
    x0 ^= t1;
    x1 ^= t2;
    x2 ^= t3;
    x3 ^= t4;
    x4 ^= t0;
    x1 ^= x0;
    x0 ^= x4;
    x3 ^= x2;
    x2 = ~x2;
    // pL: linear diffusion within each word.
    x0 ^= rrot64(x0, 19) ^ rrot64(x0, 28);
    x1 ^= rrot64(x1, 61) ^ rrot64(x1, 39);
    x2 ^= rrot64(x2, 1) ^ rrot64(x2, 6);
    x3 ^= rrot64(x3, 10) ^ rrot64(x3, 17);
    x4 ^= rrot64(x4, 7) ^ rrot64(x4, 41);
  }
  state->x[0] = x0;
  state->x[1] = x1;
  state->x[2] = x2;
  state->x[3] = x3;
  state->x[4] = x4;
}
