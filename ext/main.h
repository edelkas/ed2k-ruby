#ifndef ED2K
#define ED2K

#include <stdint.h>  // uint8_t, ...
#include <stdio.h>   // FILE
#include <stdlib.h>  // malloc, free
#include <string.h>  // memset, memcpy
#include <stdbool.h> // true, false

#include "ruby.h"

/* Entry point */
void Init_ced2k();

/* Gem functions */
VALUE md4(VALUE self, VALUE data);

/* Internal functions */
void md4_string(unsigned char* out, unsigned char* in, size_t size);
bool md4_file(unsigned char* out, const char* filename);

#endif