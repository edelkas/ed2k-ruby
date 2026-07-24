#include "main.h"

/* Names of the RC4 state variables, interned once at load rather than on every call, since the
   native cipher has to read and write all three every time it runs. */
static ID id_rc4_i, id_rc4_j, id_rc4_S;

/*
 * Entry point of the library.
 * This function gets called when it gets required in Ruby
 */
void Init_ced2k(void) {
    rb_define_global_const("C_ED2K", LONG2FIX(1));
    VALUE m_ed2k = rb_const_get(rb_cObject, rb_intern("ED2K"));
    VALUE m_hash = rb_const_get(m_ed2k, rb_intern("Hashing"));
    rb_define_module_function(m_hash, "md4", md4, 1);

    VALUE m_obfs = rb_const_get(m_ed2k, rb_intern("Obfuscation"));
    VALUE c_rc4 = rb_const_get(m_obfs, rb_intern("RC4"));
    id_rc4_i = rb_intern("@i");
    id_rc4_j = rb_intern("@j");
    id_rc4_S = rb_intern("@S");
    rb_define_private_method(c_rc4, "rc4_init_native", rc4_init, 1);
    rb_define_private_method(c_rc4, "rc4_crypt_native", rc4_crypt, 1);
}

/* Compute the MD4 hash of a string */
VALUE md4(VALUE self, VALUE data) {
  if (!RB_TYPE_P(data, T_STRING))
    rb_raise(rb_eRuntimeError, "No data to MD4 encode.");
  unsigned char* buf = (unsigned char*)RSTRING_PTR(data);
  long len = RSTRING_LEN(data);
  unsigned char hash[16];
  md4_data(hash, buf, len);
  return rb_str_new((const char*)hash, 16);
}

/* Run RC4's key scheduling algorithm and publish the resulting state into the object's @S, @i and
   @j, so that this is a drop-in replacement for the pure Ruby constructor. */
VALUE rc4_init(VALUE self, VALUE key) {
  if (!RB_TYPE_P(key, T_STRING))
    rb_raise(rb_eTypeError, "RC4 key must be a String.");
  long len = RSTRING_LEN(key);
  if (len < 1 || len > 256)
    rb_raise(rb_eArgError, "RC4 key must be between 1 and %d bytes long, got %ld.", 256, len);

  VALUE box = rb_str_new(NULL, 256);   /* Fresh, unshared binary string we own and write into directly */
  uint8_t i, j;
  RC4Init((const unsigned char*)RSTRING_PTR(key), (uint32_t)len, (uint8_t*)RSTRING_PTR(box), &i, &j, 0);

  rb_ivar_set(self, id_rc4_S, box);
  rb_ivar_set(self, id_rc4_i, INT2FIX(i));
  rb_ivar_set(self, id_rc4_j, INT2FIX(j));
  return self;
}

/* Encrypt a string in place, advancing the object's @S, @i and @j as it goes, so that this is a
   drop-in replacement for the pure Ruby cipher. */
VALUE rc4_crypt(VALUE self, VALUE buffer) {
  if (!RB_TYPE_P(buffer, T_STRING))
    rb_raise(rb_eTypeError, "RC4 can only encrypt a String.");

  VALUE box = rb_ivar_get(self, id_rc4_S);
  if (!RB_TYPE_P(box, T_STRING) || RSTRING_LEN(box) != 256)
    rb_raise(rb_eRuntimeError, "RC4 state is missing or corrupt, was the cipher initialized?");

  /* Both strings are written to, so make sure we own them before taking any pointers */
  rb_str_modify(buffer);
  rb_enc_associate(buffer, rb_ascii8bit_encoding());
  rb_str_modify(box);

  uint8_t i = (uint8_t)(NUM2LONG(rb_ivar_get(self, id_rc4_i)) & 0xFF);
  uint8_t j = (uint8_t)(NUM2LONG(rb_ivar_get(self, id_rc4_j)) & 0xFF);

  unsigned char* buf = (unsigned char*)RSTRING_PTR(buffer);
  RC4Crypt(buf, buf, (uint32_t)RSTRING_LEN(buffer), (uint8_t*)RSTRING_PTR(box), &i, &j);

  rb_ivar_set(self, id_rc4_i, INT2FIX(i));
  rb_ivar_set(self, id_rc4_j, INT2FIX(j));
  return buffer;
}