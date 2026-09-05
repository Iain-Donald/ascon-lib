/*
// ascon_aead.c
Ascon-AEAD128 // NIST SP 800-232, section 4.
*/

#include "ascon.h"
#include "ascon_perm.h"
#include "ascon_word.h"

// rate helpers //
static void rate_load(const ascon_state *s, uint8_t r[ASCON_AEAD128_RATE]) {
  ascon_store_bytes(r, s->x[0], 8);
  ascon_store_bytes(r + 8, s->x[1], 8);
}

static void rate_store(ascon_state *s, const uint8_t r[ASCON_AEAD128_RATE]) {
  s->x[0] = ascon_load_bytes(r, 8);
  s->x[1] = ascon_load_bytes(r + 8, 8);
}

// XOR a full 16-byte block into the rate.
static void rate_xor(ascon_state *s, const uint8_t *block) {
  s->x[0] ^= ascon_load_bytes(block, 8);
  s->x[1] ^= ascon_load_bytes(block + 8, 8);
}

// Add the padding bit for a partial block of n bytes (0 <= n <= 15).
static void rate_pad(ascon_state *s, size_t n) {
  if (n < 8) {
    s->x[0] ^= ascon_pad(n);
  } else {
    s->x[1] ^= ascon_pad(n - 8);
  }
}

// shared phases //
static void aead_init(ascon_state *s, const uint8_t *key,
                      const uint8_t *nonce) {
  s->x[0] = ASCON_AEAD128_IV;
  s->x[1] = ascon_load_bytes(key, 8);
  s->x[2] = ascon_load_bytes(key + 8, 8);
  s->x[3] = ascon_load_bytes(nonce, 8);
  s->x[4] = ascon_load_bytes(nonce + 8, 8);
  ascon_permute(s, 12);
  s->x[3] ^= ascon_load_bytes(key, 8);
  s->x[4] ^= ascon_load_bytes(key + 8, 8);
}

static void aead_absorb_ad(ascon_state *s, const uint8_t *ad, size_t ad_len) {
	uint8_t last[ASCON_AEAD128_RATE];
	size_t i;

	if (ad_len > 0) {
		while (ad_len >= ASCON_AEAD128_RATE) {
			rate_xor(s, ad);
			ascon_permute(s, 8);
			ad += ASCON_AEAD128_RATE;
			ad_len -= ASCON_AEAD128_RATE;
		}

		// The final associated data block is always padded and absorbed, even when it is empty.
		for (i = 0; i < ad_len; i++) last[i] = ad[i];
		for (i = ad_len; i < ASCON_AEAD128_RATE; i++) last[i] = 0;

		rate_xor(s, last);
		rate_pad(s, ad_len);
		ascon_permute(s, 8);
	}
	// Domain separation between associated data and the message.
	s->x[4] ^= ASCON_DSEP;
}

static void aead_finalize(ascon_state *s, const uint8_t *key,
                          uint8_t tag[ASCON_AEAD128_TAG_SIZE]) {
  s->x[2] ^= ascon_load_bytes(key, 8);
  s->x[3] ^= ascon_load_bytes(key + 8, 8);
  ascon_permute(s, 12);
  ascon_store_bytes(tag, s->x[3] ^ ascon_load_bytes(key, 8), 8);
  ascon_store_bytes(tag + 8, s->x[4] ^ ascon_load_bytes(key + 8, 8), 8);
}

// encrypt //
void ascon_aead128_encrypt(uint8_t *ct, uint8_t tag[ASCON_AEAD128_TAG_SIZE],
                           const uint8_t *pt, size_t pt_len, const uint8_t *ad,
                           size_t ad_len,
                           const uint8_t key[ASCON_AEAD128_KEY_SIZE],
                           const uint8_t nonce[ASCON_AEAD128_NONCE_SIZE]) {
  ascon_state s;
  uint8_t r[ASCON_AEAD128_RATE];
  size_t i;

  aead_init(&s, key, nonce);
  aead_absorb_ad(&s, ad, ad_len);

  while (pt_len >= ASCON_AEAD128_RATE) {
    rate_xor(&s, pt);
    rate_load(&s, ct);
    ascon_permute(&s, 8);
    pt += ASCON_AEAD128_RATE;
    ct += ASCON_AEAD128_RATE;
    pt_len -= ASCON_AEAD128_RATE;
  }

  // Final partial block: absorb the padded plaintext, then emit only as many ciphertext bytes as there were plaintext bytes. 
  rate_load(&s, r);
  for (i = 0; i < pt_len; i++) {
    r[i] ^= pt[i];
  }
  rate_store(&s, r);
  rate_pad(&s, pt_len);
  for (i = 0; i < pt_len; i++) {
    ct[i] = r[i];
  }
  aead_finalize(&s, key, tag);
}

// decrypt //
int ascon_aead128_decrypt(uint8_t *pt, const uint8_t *ct, size_t ct_len,
                          const uint8_t tag[ASCON_AEAD128_TAG_SIZE],
                          const uint8_t *ad, size_t ad_len,
                          const uint8_t key[ASCON_AEAD128_KEY_SIZE],
                          const uint8_t nonce[ASCON_AEAD128_NONCE_SIZE]) {
  ascon_state s;
  uint8_t r[ASCON_AEAD128_RATE];
  uint8_t expected[ASCON_AEAD128_TAG_SIZE];
  uint8_t diff = 0;
  uint8_t *pt_start = pt;
  size_t pt_len = ct_len;
  size_t i;

  aead_init(&s, key, nonce);
  aead_absorb_ad(&s, ad, ad_len);

  while (ct_len >= ASCON_AEAD128_RATE) {
    rate_load(&s, r);
    for (i = 0; i < ASCON_AEAD128_RATE; i++) pt[i] = r[i] ^ ct[i];
    
    // The rate is replaced by the ciphertext rather than XORed.
    rate_store(&s, ct);
    ascon_permute(&s, 8);
    pt += ASCON_AEAD128_RATE;
    ct += ASCON_AEAD128_RATE;
    ct_len -= ASCON_AEAD128_RATE;
  }

  rate_load(&s, r);
  for (i = 0; i < ct_len; i++) {
    pt[i] = r[i] ^ ct[i];
    r[i] = ct[i];
  }
  rate_store(&s, r);
  rate_pad(&s, ct_len);

  aead_finalize(&s, key, expected);

  // Compare in constant time: no early exit, no data-dependent branch.
  for (i = 0; i < ASCON_AEAD128_TAG_SIZE; i++) diff |= expected[i] ^ tag[i];
  if (diff != 0) {
    // Do not release unauthenticated plaintext.
    for (i = 0; i < pt_len; i++) pt_start[i] = 0;
    return ASCON_ERR_TAG;
  }
  return ASCON_OK;
}
