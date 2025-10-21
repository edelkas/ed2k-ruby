#include "main.h"

/*
 * Entry point of the library.
 * This function gets called when it gets required in Ruby
 */
void Init_ced2k() {
    rb_define_global_const("C_ED2K", LONG2FIX(1));
    VALUE m_ed2k = rb_const_get(rb_cObject, rb_intern("ED2K"));
    VALUE m_hash = rb_const_get(m_ed2k, rb_intern("Hash"));
    rb_define_singleton_method(m_hash, "md4", md4, 1);
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