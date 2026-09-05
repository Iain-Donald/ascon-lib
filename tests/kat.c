/*
kat.c
known-answer tests against the LWC vector files.
Checks the functions in this library against the ascon-c vector files. Exits non-zero if any fail.

// usage
kat [vector_directory]
// default directory
tests/vectors

Record format: fields of the form "Name = HEXSTRING", one per line, with a blank line between records. An empty value is a zero-length input, not a missing field.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ascon.h"

#define MAX_BYTES 2048
#define MAX_LINE (2 * MAX_BYTES + 64)
#define MAX_FIELDS 8
#define MAX_NAME 16

typedef enum {
	AS_SERROR = -1,
	AS_OK = 0,
	AS_ERROR = 1,
} AsconStatus;

// Hex and line parsing.
static int hex_digit(int c) {
	if (c >= '0' && c <= '9') return c - '0';
	if (c >= 'a' && c <= 'f') return c - 'a' + 10;
	if (c >= 'A' && c <= 'F') return c - 'A' + 10;
	return AS_SERROR;
}

// Decode a hex string into bytes. Returns the byte count or -1 on a malformed string. Empty string = zero bytes.
static long hex_decode(const char *hex, uint8_t *out, size_t out_max) {
	size_t length = strlen(hex);
	size_t i;
	if (length % 2 != 0) return AS_SERROR;
	if (length / 2 > out_max) return AS_SERROR;

	for (i = 0; i < length; i += 2) {
		int high = hex_digit((unsigned char)hex[i]);
		int low = hex_digit((unsigned char)hex[i + 1]);
		if (high < 0 || low < 0) return AS_SERROR;
		out[i / 2] = (uint8_t)((high << 4) | low);
	}
	return (long)(length / 2);
}

// One "Name = value" pair.
typedef struct {
	char name[MAX_NAME];
	char value[MAX_LINE];
} field;

// A record is the set of fields between blank lines.
typedef struct {
	field fields[MAX_FIELDS];
	size_t count;
} record;

static const char *record_get(const record *rec, const char *name) {
	size_t i;
	for (i = 0; i < rec->count; i++) {
		if (strcmp(rec->fields[i].name, name) == 0)
			return rec->fields[i].value;
	}
	return NULL;
}

// Decode a named field into bytes. Returns -1 if the field is absent or malformed. A present but empty field yields 0.
static long record_bytes(const record *rec, const char *name, uint8_t *out, size_t out_max) {
	const char *value = record_get(rec, name);
	if (value == NULL) return AS_SERROR;
	return hex_decode(value, out, out_max);
}

// Strip trailing whitespace, including CR from files with DOS endings.
static void rstrip(char *str) {
	size_t n = strlen(str);
	while (n > 0 && (str[n - 1] == '\n' || str[n - 1] == '\r' || str[n - 1] == ' ' || str[n - 1] == '\t'))
		str[--n] = '\0';
}

// Split "Name = value" into a field. Returns 0 on success.
static int parse_field(char *line, field *out) {
	char *eq = strchr(line, '=');
	char *name_end;
	size_t name_length;
	const char *value;

	if (eq == NULL) return AS_SERROR;

	// Name: everything before '=', trimmed.
	name_end = eq;
	while (name_end > line && (name_end[-1] == ' ' || name_end[-1] == '\t'))
		name_end--;

	name_length = (size_t)(name_end - line);
	if (name_length == 0 || name_length >= MAX_NAME) return AS_ERROR;
	memcpy(out->name, line, name_length);
	out->name[name_length] = '\0';

	// Value: everything after '=', leading spaces skipped. May be empty.
	value = eq + 1;
	while (*value == ' ' || *value == '\t') value++;
	if (strlen(value) >= MAX_LINE) return AS_SERROR;
	strcpy(out->value, value);
	return AS_OK;
}

///// Test driver /////
typedef struct {
	unsigned long passed;
	unsigned long failed;
	unsigned long skipped;
} tally;

// Detailed output is capped: a systematic break fails every record, and a few hundred hex dumps bury the useful, first failure. Remaining failures are still counted.

// Detail is collected into a buffer rather than printed directly, so the "FAIL at Count = N" header can be emitted first, only once the record is known to have failed.
#define MAX_REPORTED 3
#define DETAIL_MAX (4 * MAX_BYTES + 256)

static char detail[DETAIL_MAX];
static size_t detail_len;
static void detail_reset(void) {
	detail[0] = '\0';
	detail_len = 0;
}

static void detail_puts(const char *s) {
	size_t n = strlen(s);
	if (detail_len + n + 1 >= DETAIL_MAX) return;
	memcpy(detail + detail_len, s, n + 1);
	detail_len += n;
}

static void detail_hex(const uint8_t *data, size_t len) {
	size_t i;
	for (i = 0; i < len; i++) {
		if (detail_len + 3 >= DETAIL_MAX) return;
		sprintf(detail + detail_len, "%02X", data[i]);
		detail_len += 2;
	}
}

static void report(const char *what, const uint8_t *expected, const uint8_t *actual, size_t len) {
	detail_puts("    ");
	detail_puts(what);
	detail_puts("\n    expected ");
	detail_hex(expected, len);
	detail_puts("\n    actual   ");
	detail_hex(actual, len);
	detail_puts("\n");
}

static void note(const char *msg) {
	detail_puts("    ");
	detail_puts(msg);
	detail_puts("\n");
}

// A per-mode check. Return 1 if the record passed, 0 if failed. Sets *skip if the record lacks the fields this mode needs.
typedef int (*check_fn)(const record *rec, int *skip);

///// Hash256 /////
static int check_hash(const record *rec, int *skip) {
	uint8_t msg[MAX_BYTES];
	uint8_t expected[MAX_BYTES];
	uint8_t actual[ASCON_HASH256_SIZE];
	long msg_len, md_len;

	msg_len = record_bytes(rec, "Msg", msg, sizeof msg);
	md_len = record_bytes(rec, "MD", expected, sizeof expected);
	if (msg_len < 0 || md_len < 0) {
		*skip = 1;
		return AS_OK;
	}

	if (md_len != ASCON_HASH256_SIZE) {
		note("unexpected MD length");
		return AS_OK;
	}

	ascon_hash256(actual, msg, (size_t)msg_len);
	if (memcmp(actual, expected, ASCON_HASH256_SIZE) != 0) {
		report("digest mismatch", expected, actual, ASCON_HASH256_SIZE);
		return AS_OK;
	}
	return AS_ERROR;
}

///// XOF128 /////
static int check_xof(const record *rec, int *skip) {
	uint8_t msg[MAX_BYTES];
	uint8_t expected[MAX_BYTES];
	uint8_t actual[MAX_BYTES];
	uint8_t chunked[MAX_BYTES];
	ascon_xof128_ctx ctx;
	long msg_len, md_len;
	long i;

	msg_len = record_bytes(rec, "Msg", msg, sizeof msg);
	md_len = record_bytes(rec, "MD", expected, sizeof expected);
	if (msg_len < 0 || md_len < 0) {
		*skip = 1;
		return AS_OK;
	}

	ascon_xof128(actual, (size_t)md_len, msg, (size_t)msg_len);
	if (memcmp(actual, expected, (size_t)md_len) != 0) {
		report("digest mismatch", expected, actual, (size_t)md_len);
		return AS_OK;
	}

	// The same output must come back one byte at a time, which exercises the resumable squeeze that the vector files do not cover.
	ascon_xof128_init(&ctx);
	for (i = 0; i < msg_len; i++)
		ascon_xof128_update(&ctx, msg + i, 1);
	for (i = 0; i < md_len; i++)
		ascon_xof128_squeeze(&ctx, chunked + i, 1);
	if (memcmp(chunked, expected, (size_t)md_len) != 0) {
		note("incremental path disagrees with one-shot");
		return AS_OK;
	}
	return AS_ERROR;
}

///// CXOF-128 /////
static int check_cxof(const record *rec, int *skip) {
	uint8_t msg[MAX_BYTES];
	uint8_t cs[MAX_BYTES];
	uint8_t expected[MAX_BYTES];
	uint8_t actual[MAX_BYTES];
	uint8_t chunked[MAX_BYTES];
	ascon_cxof128_ctx ctx;
	long msg_len, cs_len, md_len;
	long i;

	msg_len = record_bytes(rec, "Msg", msg, sizeof msg);
	cs_len = record_bytes(rec, "Z", cs, sizeof cs);
	md_len = record_bytes(rec, "MD", expected, sizeof expected);
	if (msg_len < 0 || cs_len < 0 || md_len < 0) {
		*skip = 1;
		return AS_OK;
	}

	if (ascon_cxof128(actual, (size_t)md_len, msg, (size_t)msg_len, cs, (size_t)cs_len) != ASCON_OK) {
		note("one-shot returned an error");
		return AS_OK;
	}
	if (memcmp(actual, expected, (size_t)md_len) != 0) {
		report("digest mismatch", expected, actual, (size_t)md_len);
		return AS_OK;
	}

	if (ascon_cxof128_init(&ctx, cs, (size_t)cs_len) != ASCON_OK) {
		note("init returned an error");
		return AS_OK;
	}
	for (i = 0; i < msg_len; i++)
		ascon_cxof128_update(&ctx, msg + i, 1);
	for (i = 0; i < md_len; i++)
		ascon_cxof128_squeeze(&ctx, chunked + i, 1);
	if (memcmp(chunked, expected, (size_t)md_len) != 0) {
		note("incremental path disagrees with one-shot");
		return AS_OK;
	}
	return AS_ERROR;
}

///// AEAD-128 ////

static int check_aead(const record *rec, int *skip) {
	uint8_t key[MAX_BYTES];
	uint8_t nonce[MAX_BYTES];
	uint8_t pt[MAX_BYTES];
	uint8_t ad[MAX_BYTES];
	uint8_t expected[MAX_BYTES];
	uint8_t ct[MAX_BYTES];
	uint8_t tag[ASCON_AEAD128_TAG_SIZE];
	uint8_t recovered[MAX_BYTES];
	uint8_t bad_tag[ASCON_AEAD128_TAG_SIZE];
	long key_len, nonce_len, pt_len, ad_len, ct_len;
	size_t expected_ct_len;

	key_len = record_bytes(rec, "Key", key, sizeof key);
	nonce_len = record_bytes(rec, "Nonce", nonce, sizeof nonce);
	pt_len = record_bytes(rec, "PT", pt, sizeof pt);
	ad_len = record_bytes(rec, "AD", ad, sizeof ad);
	ct_len = record_bytes(rec, "CT", expected, sizeof expected);
	if (key_len < 0 || nonce_len < 0 || pt_len < 0 || ad_len < 0 || ct_len < 0) {
		*skip = 1;
		return AS_OK;
	}

	if (key_len != ASCON_AEAD128_KEY_SIZE || nonce_len != ASCON_AEAD128_NONCE_SIZE) {
		note("unexpected key or nonce length");
		return AS_OK;
	}

	// The vector files carry the tag appended to the ciphertext; this library keeps them separate.
	if (ct_len != pt_len + ASCON_AEAD128_TAG_SIZE) {
		note("CT length does not equal PT length plus tag");
		return AS_OK;
	}
	expected_ct_len = (size_t)pt_len;

	ascon_aead128_encrypt(ct, tag, pt, (size_t)pt_len, ad, (size_t)ad_len, key, nonce);

	if (memcmp(ct, expected, expected_ct_len) != 0) {
		report("ciphertext mismatch", expected, ct, expected_ct_len);
		return AS_OK;
	}
	if (memcmp(tag, expected + expected_ct_len, ASCON_AEAD128_TAG_SIZE) != 0) {
		report("tag mismatch", expected + expected_ct_len, tag, ASCON_AEAD128_TAG_SIZE);
		return AS_OK;
	}

	// Decrypting must recover the plaintext.
	if (ascon_aead128_decrypt(recovered, ct, expected_ct_len, tag, ad, (size_t)ad_len, key, nonce) != ASCON_OK) {
		note("decrypt rejected a valid tag");
		return AS_OK;
	}
	if (memcmp(recovered, pt, (size_t)pt_len) != 0) {
		note("decrypt returned the wrong plaintext");
		return AS_OK;
	}

	// A corrupted tag must be rejected. The vector files contain no negative cases, so this one is constructed here.
	memcpy(bad_tag, tag, sizeof bad_tag);
	bad_tag[0] ^= 0x01;
	if (ascon_aead128_decrypt(recovered, ct, expected_ct_len, bad_tag, ad, (size_t)ad_len, key, nonce) != ASCON_ERR_TAG) {
		note("decrypt accepted a corrupted tag");
		return AS_OK;
	}
	return AS_ERROR;
}

// File walking.
static void run_record(const record *rec, check_fn check, tally *t) {
	const char *count = record_get(rec, "Count");
	int skip = 0;
	if (rec->count == 0) return;

	detail_reset();

	if (check(rec, &skip)) {
		t->passed++;
		return;
	}
	if (skip) {
		t->skipped++;
		return;
	}

	t->failed++;
	if (t->failed <= MAX_REPORTED)
		printf("  FAIL at Count = %s\n%s", count ? count : "?", detail);
	else if (t->failed == MAX_REPORTED + 1)
		printf("  (further failures suppressed)\n");
}

static int run_file(const char *path, const char *label, check_fn check) {
	FILE *f = fopen(path, "r");
	char line[MAX_LINE];
	record rec;
	tally t;

	t.passed = 0;
	t.failed = 0;
	t.skipped = 0;
	rec.count = 0;

	if (f == NULL) {
		printf("%-10s ERROR cannot open %s\n", label, path);
		return AS_ERROR;
	}

	while (fgets(line, sizeof line, f) != NULL) {
		rstrip(line);

		if (line[0] == '\0') {
			// Blank line ends a record.
			run_record(&rec, check, &t);
			rec.count = 0;
			continue;
		}

		if (rec.count < MAX_FIELDS)
			if (parse_field(line, &rec.fields[rec.count]) == 0)
				rec.count++;
	}

	// A file may end without a trailing blank line.
	run_record(&rec, check, &t);
	fclose(f);

	printf("%-10s %s  %lu passed", label, t.failed ? "FAIL" : "ok  ", t.passed);
	if (t.failed) printf(", %lu failed", t.failed);
	if (t.skipped) printf(", %lu skipped", t.skipped);
	printf("\n");

	return t.failed != 0 || t.passed == 0;
}

int main(int argc, char **argv) {
	const char *dir = (argc > 1) ? argv[1] : "tests/vectors";
	char path[1024];
	int bad = 0;

	printf("vectors: %s\n\n", dir);

	sprintf(path, "%s/LWC_HASH_KAT_128_256.txt", dir);
	bad |= run_file(path, "Hash256", check_hash);

	sprintf(path, "%s/LWC_XOF_KAT_128_512.txt", dir);
	bad |= run_file(path, "XOF128", check_xof);

	sprintf(path, "%s/LWC_CXOF_KAT_128_512.txt", dir);
	bad |= run_file(path, "CXOF128", check_cxof);

	sprintf(path, "%s/LWC_AEAD_KAT_128_128.txt", dir);
	bad |= run_file(path, "AEAD128", check_aead);

	printf("\n%s\n", bad ? "FAILED" : "all vectors passed");
	return bad ? 1 : 0;
}
