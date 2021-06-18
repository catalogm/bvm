
#include <argon2.h>
#include <gcrypt.h>
#include <stdio.h>

#include "bvm/bvm.h"

bvm_key_t* bvm_key_create_zero(size_t size) {
  if (size < 1) {
    fprintf(stderr, "bvm_key_create: Invalid random key size\n");
    return NULL;
  }

  uint8_t* data = gcry_calloc(1, size);
  if (data == NULL) {
    fprintf(stderr, "bvm_key_create: Failed to alloc secure key data\n");
    return NULL;
  }

  bvm_key_t* key = gcry_calloc(1, sizeof(bvm_key_t));
  if (key == NULL) {
    fprintf(stderr,
            "bvm_key_create: Failed to allocate secure memory for key\n");
    gcry_free(data);
    return NULL;
  }

  key->data = data;
  key->size = size;
  return key;
}

bvm_key_t* bvm_key_create(const uint8_t* orig_data, size_t size) {
  if (orig_data == NULL) {
    fprintf(stderr, "bvm_key_create: data must not be null\n");
    return NULL;
  }

  bvm_key_t* key = bvm_key_create_zero(size);
  if (key == NULL) {
    return NULL;
  }
  memcpy(key->data, orig_data, size);
  return key;
}

bvm_key_t* bvm_key_create_random(size_t size) {
  bvm_key_t* key = bvm_key_create_zero(size);
  if (key == NULL) {
    return NULL;
  }
  gcry_randomize(key->data, key->size, GCRY_VERY_STRONG_RANDOM);
  return key;
}

bvm_key_t* bvm_key_create_argon2id(const uint32_t t_cost, const uint32_t m_cost,
                                   const uint32_t parallelism, const void* pwd,
                                   const size_t pwdlen, const void* salt,
                                   const size_t saltlen, const size_t size) {
  bvm_key_t* key = bvm_key_create_zero(size);
  if (key == NULL) {
    return NULL;
  }

  int res = argon2id_hash_raw(t_cost, m_cost, parallelism, pwd, pwdlen, salt,
                              saltlen, key->data, key->size);
  if (res != ARGON2_OK) {
    return NULL;
  }
  return key;
}

bvm_key_t* bvm_key_dup(const bvm_key_t* key) {
  if (key == NULL) {
    return NULL;
  }
  return bvm_key_create(key->data, key->size);
}

void bvm_key_free(bvm_key_t* key) {
  if (key != NULL) {
    if (key->data != NULL) {
      memset(key->data, 0, key->size);
      gcry_free(key->data);
    }
    gcry_free(key);
  }
}

