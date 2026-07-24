#include <stddef.h> // NULL
#include <stdint.h>

static inline void swap(uint8_t *a, uint8_t *b) {
	uint8_t aux = *a;
	*a = *b;
	*b = aux;
}

/* Encrypt len bytes from input to output, advancing the state S and the indices i and j in place.
   Pass input == NULL to only advance the state (used to skip keystream); output may then be NULL too.
   S is worked on directly, and i and j are read once into locals and written back at the end. */
void RC4Crypt(const unsigned char *input, unsigned char *output, uint32_t len, uint8_t *S, uint8_t *ip, uint8_t *jp) {
	uint8_t i = *ip;
	uint8_t j = *jp;
	uint8_t t;
	for (uint32_t n = 0; n < len; ++n) {
		j += S[++i];
		swap(&S[i], &S[j]);
		t = (S[i] + S[j]);
		if (input != NULL) output[n] = input[n] ^ S[t];
	}
	*ip = i;
	*jp = j;
}

/* Run the key scheduling algorithm, filling the 256-byte state S and setting the indices i and j.
   S must point to at least 256 writable bytes; here it's the buffer of the Ruby @S string,
   so the permutation is built in place with no copy. skip discards that many keystream bytes up front. */
void RC4Init(const unsigned char *key, uint32_t len, uint8_t *S, uint8_t *i, uint8_t *j, int skip) {
	for (uint32_t k = 0; k < 256; ++k) S[k] = (uint8_t)k;
	*i = 0;
	*j = 0;
	uint8_t index1 = 0;
	uint8_t index2 = 0;
	for (uint32_t k = 0; k < 256; ++k) {
		index2 += key[index1] + S[k];
		swap(&S[k], &S[index2]);
		index1 = (uint8_t)((index1 + 1) % len);
	}
	if (skip > 0) RC4Crypt(NULL, NULL, skip, S, i, j);
}