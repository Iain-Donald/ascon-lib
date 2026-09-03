/*
ascon_perm.h - the Ascon permutation (NIST SP 800-232, Sec. 3)
*/

#ifndef ASCON_PERM_H
#define ASCON_PERM_H

#include "ascon.h"

// Initial values, SP 800-232 Table 14.
#define ASCON_AEAD128_IV 0x00001000808c0001ULL
#define ASCON_HASH256_IV 0x0000080100cc0002ULL
#define ASCON_XOF128_IV 0x0000080000cc0003ULL
#define ASCON_CXOF128_IV 0x0000080000cc0004ULL

// Rates in bytes.
#define ASCON_AEAD128_RATE 16
#define ASCON_HASH_RATE 8

// Ascon-p[rnd] for 1<=rnd<=16.
void ascon_permute(ascon_state *s, int rounds);

#endif
