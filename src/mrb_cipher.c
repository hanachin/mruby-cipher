/*
** mrb_cipher.c - Cipher
**
** Copyright (c) Seiei Miyagi 2017
**
** See Copyright Notice in LICENSE
*/

#include <mruby.h>
#include <mruby/array.h>
#include <mruby/class.h>
#include <mruby/data.h>
#include <mruby/string.h>
#include <mruby/variable.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/opensslv.h>
#include "mrb_cipher.h"

#define DONE mrb_gc_arena_restore(mrb, 0);

#define E_CIPHER_ERROR (mrb_class_get_under(mrb, mrb_class_get(mrb, "Cipher"), "CipherError"))

struct mrb_cipher {
  EVP_CIPHER_CTX ctx;
};
static void cipher_free(mrb_state *mrb, void *ptr);
static const struct mrb_data_type mrb_cipher_type = { "Cipher", cipher_free };

struct cipher_names {
  mrb_state *mrb;
  mrb_value *ary;
};

const char *
openssl_error_message()
{
  const char *msg;
  long e;

  e = ERR_peek_last_error();
  if (e) {
    msg = ERR_reason_error_string(e);
  } else {
    msg = NULL;
  }

  ERR_clear_error();

  return msg;
}

struct mrb_cipher*
cipher_get_ptr(mrb_state *mrb, mrb_value self)
{
  return DATA_GET_PTR(mrb, self, &mrb_cipher_type, struct mrb_cipher);
}

static void*
add_cipher_name_to_ary(const OBJ_NAME *name, struct cipher_names *cn)
{
  mrb_ary_push(cn->mrb, *cn->ary, mrb_str_new_cstr(cn->mrb, name->name));
  return NULL;
}

static mrb_value
cipher_s_ciphers(mrb_state *mrb, mrb_value self)
{
  mrb_value ary = mrb_ary_new(mrb);
  struct cipher_names cn = {mrb, &ary};
  OBJ_NAME_do_all_sorted(OBJ_NAME_TYPE_CIPHER_METH,
                         (void(*)(const OBJ_NAME*,void*))add_cipher_name_to_ary,
                         (void*)&cn);
  return ary;
}

static void
cipher_free(mrb_state *mrb, void *ptr)
{
  struct mrb_cipher *c = ptr;

  EVP_CIPHER_CTX_cleanup(&c->ctx);

  mrb_free(mrb, c);
}


static mrb_value
cipher_initialize(mrb_state *mrb, mrb_value self)
{
  char *name;
  struct mrb_cipher *c;
  const EVP_CIPHER *cipher;

  mrb_get_args(mrb, "z", &name);

  c = (struct mrb_cipher *)mrb_malloc(mrb, sizeof(*c));

  EVP_CIPHER_CTX_init(&c->ctx);

  if (!(cipher = EVP_get_cipherbyname(name))) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "unsupported cipher algorithm (%S)", mrb_str_new_cstr(mrb, name));
  }

  if (EVP_CipherInit_ex(&c->ctx, cipher, NULL, NULL, NULL, -1) != 1) {
    mrb_raise(mrb, E_CIPHER_ERROR, openssl_error_message());
  }

  mrb_data_init(self, c, &mrb_cipher_type);

  return self;
}

static mrb_value
cipher_decrypt(mrb_state *mrb, mrb_value self)
{
  struct mrb_cipher *c = cipher_get_ptr(mrb, self);

  if (EVP_CipherInit_ex(&c->ctx, NULL, NULL, NULL, NULL, 0) != 1) {
    mrb_raise(mrb, E_CIPHER_ERROR, "CipherError");
  }

  return self;
}

static mrb_value
cipher_encrypt(mrb_state *mrb, mrb_value self)
{
  struct mrb_cipher *c = cipher_get_ptr(mrb, self);

  if (EVP_CipherInit_ex(&c->ctx, NULL, NULL, NULL, NULL, 1) != 1) {
    mrb_raise(mrb, E_CIPHER_ERROR, openssl_error_message());
  }

  return self;
}

static mrb_value
cipher_set_key(mrb_state *mrb, mrb_value self)
{

  struct mrb_cipher *c;
  mrb_value key;
  int key_len;

  c = cipher_get_ptr(mrb, self);
  mrb_get_args(mrb, "S", &key);
  key_len = EVP_CIPHER_CTX_key_length(&c->ctx);

  if (RSTRING_LEN(key) != key_len) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "key must be %S bytes", mrb_fixnum_value(key_len));
  }

  if (EVP_CipherInit_ex(&c->ctx, NULL, NULL, (const unsigned char *)RSTRING_PTR(key), NULL, -1) != 1) {
    mrb_raise(mrb, E_CIPHER_ERROR, openssl_error_message());
  }

  mrb_iv_set(mrb, self, mrb_intern_lit(mrb, "key_set"), mrb_true_value());

  return key;
}

static mrb_value
cipher_set_iv(mrb_state *mrb, mrb_value self)
{
  struct mrb_cipher *c;
  mrb_value iv;
  int iv_len;

  c = cipher_get_ptr(mrb, self);
  mrb_get_args(mrb, "S", &iv);
  iv_len = EVP_CIPHER_CTX_iv_length(&c->ctx);

  if (RSTRING_LEN(iv) != iv_len) {
    mrb_raisef(mrb, E_ARGUMENT_ERROR, "iv must be %S bytes", mrb_fixnum_value(iv_len));
  }

  if (EVP_CipherInit_ex(&c->ctx, NULL, NULL, NULL, (const unsigned char *)RSTRING_PTR(iv), -1) != 1) {
    mrb_raise(mrb, E_CIPHER_ERROR, openssl_error_message());
  }

  return iv;
}

static mrb_value
cipher_set_padding(mrb_state *mrb, mrb_value self)
{
  struct mrb_cipher *c;
  mrb_value padding;

  c = cipher_get_ptr(mrb, self);
  mrb_get_args(mrb, "i", &padding);
  if (EVP_CIPHER_CTX_set_padding(&c->ctx, mrb_fixnum(padding)) != 1) {
    mrb_raise(mrb, E_CIPHER_ERROR, openssl_error_message());
  }
  return padding;
}

static mrb_value
cipher_update(mrb_state *mrb, mrb_value self)
{
  struct mrb_cipher *c;
  mrb_value data, out_data;
  unsigned char *in, *out;
  int in_len, out_len;

  c = cipher_get_ptr(mrb, self);
  mrb_get_args(mrb, "S", &data);

  if (!mrb_iv_defined(mrb, self, mrb_intern_lit(mrb, "key_set"))) {
    mrb_raise(mrb, E_CIPHER_ERROR, "key not set");
  }

  in = (unsigned char *)RSTRING_PTR(data);
  in_len = RSTRING_LEN(data);
  if (in_len == 0) {
    mrb_raise(mrb, E_ARGUMENT_ERROR, "data must not be empty");
  }

  out_len = in_len + EVP_CIPHER_CTX_block_size(&c->ctx);
  if (out_len <= 0) {
    mrb_raisef(mrb, E_RANGE_ERROR, "data too big to make output buffer: %ld bytes", in_len);
  }
  out_data = mrb_str_buf_new(mrb, out_len);
  out = (unsigned char *)RSTRING_PTR(out_data);

  // FIXME output may overflow
  if (!EVP_CipherUpdate(&c->ctx, out, &out_len, in, in_len)) {
    mrb_raise(mrb, E_CIPHER_ERROR, openssl_error_message());
  }
  mrb_assert(out_len < RSTRING_LEN(out_data));
  RSTR_SET_LEN(mrb_str_ptr(out_data), out_len);

  return out_data;
}

static mrb_value
cipher_final(mrb_state *mrb, mrb_value self)
{
  struct mrb_cipher *c;
  mrb_value out_data;
  int out_len;

  c = cipher_get_ptr(mrb, self);

  out_data = mrb_str_buf_new(mrb, EVP_CIPHER_CTX_block_size(&c->ctx));
  if (!EVP_CipherFinal_ex(&c->ctx, (unsigned char *)RSTRING_PTR(out_data), &out_len)) {
    mrb_raise(mrb, E_CIPHER_ERROR, openssl_error_message());
  }
  mrb_assert(out_len <= RSTRING_LEN(out_data));
  RSTR_SET_LEN(mrb_str_ptr(out_data), out_len);

  return out_data;
}

void
mrb_mruby_cipher_gem_init(mrb_state* mrb)
{
  struct RClass *cipher;

  OpenSSL_add_all_algorithms();

  cipher = mrb_define_class(mrb, "Cipher", mrb->object_class);
  MRB_SET_INSTANCE_TT(cipher, MRB_TT_DATA);

  mrb_define_class_under(mrb, cipher, "CipherError", mrb->eStandardError_class);

  mrb_define_class_method(mrb, cipher, "ciphers", cipher_s_ciphers, MRB_ARGS_ANY());
  mrb_define_method(mrb, cipher, "initialize", cipher_initialize, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cipher, "decrypt", cipher_decrypt, MRB_ARGS_ANY());
  mrb_define_method(mrb, cipher, "encrypt", cipher_encrypt, MRB_ARGS_ANY());
  mrb_define_method(mrb, cipher, "key=", cipher_set_key, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cipher, "iv=", cipher_set_iv, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cipher, "padding=", cipher_set_padding, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cipher, "update", cipher_update, MRB_ARGS_REQ(1));
  mrb_define_method(mrb, cipher, "final", cipher_final, MRB_ARGS_ANY());
  DONE;
}

void
mrb_mruby_cipher_gem_final(mrb_state* mrb)
{
  EVP_cleanup();
}
