/*
demo.c
A brief tour of the Ascon API :)
*/

#include <stdio.h>
#include <string.h>
#include "ascon.h"

static void print_hex(const char *label, const uint8_t *data, size_t len) {
  size_t i;
  printf("%-24s", label);
  for (i = 0; i < len; i++)
    printf("%02x", data[i]);
  printf("\n");
}

static void demo_hash(void) {
  const char *msg = "hello ascon";
  uint8_t digest[ASCON_HASH256_SIZE];
  ascon_hash256_ctx ctx;

  printf("--- Ascon-Hash256 ---\n");

  //One-shot convenience wrapper.
  ascon_hash256(digest, (const uint8_t *)msg, strlen(msg));
  print_hex("one-shot:", digest, sizeof digest);

  // The same message fed in two pieces.
  ascon_hash256_init(&ctx);
  ascon_hash256_update(&ctx, (const uint8_t *)msg, 5);
  ascon_hash256_update(&ctx, (const uint8_t *)msg + 5, strlen(msg) - 5);
  ascon_hash256_final(&ctx, digest);
  print_hex("incremental:", digest, sizeof digest);
  printf("\n");
}

static void demo_xof(void) {
  const char *msg = "hello ascon";
  uint8_t out[64];
  uint8_t prefix[16];

  printf("--- Ascon-XOF128 ---\n");

  // Output length is chosen by the caller.
  ascon_xof128(out, sizeof out, (const uint8_t *)msg, strlen(msg));
  print_hex("64 bytes:", out, sizeof out);

  // A shorter request is a prefix of a longer one.
  ascon_xof128(prefix, sizeof prefix, (const uint8_t *)msg, strlen(msg));
  print_hex("16 bytes:", prefix, sizeof prefix);
  printf("%-24s%s\n", "is a prefix:",
         memcmp(out, prefix, sizeof prefix) == 0 ? "yes" : "no");

  printf("\n");
}

static void demo_cxof(void) {
  const char *msg = "hello ascon";
  uint8_t out[32];

  printf("--- Ascon-CXOF128 ---\n");

  // The customization string separates domains: the same message under different customizations produces unrelated output.
  ascon_cxof128(out, sizeof out, (const uint8_t *)msg, strlen(msg), (const uint8_t *)"signing-key", 11);
  print_hex("cs=signing-key:", out, sizeof out);
  ascon_cxof128(out, sizeof out, (const uint8_t *)msg, strlen(msg), (const uint8_t *)"encryption-key", 14);
  print_hex("cs=encryption-key:", out, sizeof out);
  printf("\n");
}

static void demo_aead(void) {
  const uint8_t key[ASCON_AEAD128_KEY_SIZE] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
  const uint8_t nonce[ASCON_AEAD128_NONCE_SIZE] = { 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
  const char *plaintext = "attack at dawn";
  const char *header = "to:bob";
  size_t pt_len = strlen(plaintext);

  uint8_t ciphertext[64];
  uint8_t tag[ASCON_AEAD128_TAG_SIZE];
  uint8_t recovered[64];
  int rc;

  printf("--- Ascon-AEAD128 ---\n");

  ascon_aead128_encrypt(ciphertext, tag, (const uint8_t *)plaintext, pt_len, (const uint8_t *)header, strlen(header), key, nonce);
  print_hex("ciphertext:", ciphertext, pt_len);
  print_hex("tag:", tag, sizeof tag);

  // The associated data is authenticated but not encrypted, so the receiver must supply the same bytes.
  rc = ascon_aead128_decrypt(recovered, ciphertext, pt_len, tag, (const uint8_t *)header, strlen(header), key, nonce);
  if (rc == ASCON_OK)
    printf("%-24s%.*s\n", "decrypted:", (int)pt_len, (const char *)recovered);
  else
    printf("%-24sauthentication failed\n", "decrypted:");

  // Tampering with the associated data invalidates the tag even though the ciphertext is untouched.
  rc = ascon_aead128_decrypt(recovered, ciphertext, pt_len, tag, (const uint8_t *)"to:eve", 6, key, nonce);
  printf("%-24s%s\n", "forged header:", rc == ASCON_ERR_TAG ? "rejected" : "ACCEPTED (bug!)");
  printf("\n");
}

int main(void) {
  demo_hash();
  demo_xof();
  demo_cxof();
  demo_aead();
  return 0;
}
