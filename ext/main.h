#ifndef ED2K
#define ED2K

#include <stdint.h>  // uint8_t, ...
#include <stdio.h>   // FILE
#include <stdlib.h>  // malloc, free
#include <string.h>  // memset, memcpy
#include <stdbool.h> // true, false

#include "ruby.h"
#include "ruby/encoding.h"

/* Entry point */
void Init_ced2k(void);

/* Gem functions */
VALUE md4(VALUE self, VALUE data);
VALUE rc4_init(VALUE self, VALUE key);
VALUE rc4_crypt(VALUE self, VALUE buffer);

/* Internal functions */
void md4_data(unsigned char* out, unsigned char* in, size_t size);
bool md4_file(unsigned char* out, const char* filename);
void RC4Init(const unsigned char *key, uint32_t len, uint8_t *S, uint8_t *i, uint8_t *j, int skip);
void RC4Crypt(const unsigned char *input, unsigned char *output, uint32_t len, uint8_t *S, uint8_t *i, uint8_t *j);

#endif