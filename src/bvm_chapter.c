/* Copyright 2021 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <cbor.h>
#include <gcrypt.h>
#include <stdio.h>
#include <stdlib.h>

#include "bvm/bvm.h"
#include "log.h"

// interal function to generate chapter keys during chapter creation
static bvm_errcode_t _bvm_chapter_create_generate_keys(const bvm_key_t* key,
                                                       bvm_chapter_t* ch,
                                                       bvm_key_t** out_salt) {
  *out_salt = NULL;

  // generate keys
  bvm_key_t* page_key = bvm_key_create_random(256 / 8);
  if (page_key == NULL) {
    log_error("bvm_chapter_create: failed to allocate memory for page key");
    goto chapter_generate_keys_fail_page;
  }

  bvm_key_t* salt = bvm_key_create_random(BVM_CHAPTER_SLOT_SALT_SIZE);
  if (salt == NULL) {
    log_error("bvm_chapter_create: failed to allocate memory for salt");
    goto chapter_generate_keys_fail_salt;
  }

  // generate slot key with iv, used to encrypt slot payload
  bvm_key_t* slot_iv_key = bvm_key_create_argon2id(
      BVM_CHAPTER_SLOT_ARGON2_DEFAULT_ITERATIONS,
      BVM_CHAPTER_SLOT_ARGON2_DEFAULT_MEMORY,
      BVM_CHAPTER_SLOT_ARGON2_DEFAULT_PARALLELISM, key->data, key->size,
      salt->data, salt->size,
      BVM_CHAPTER_SLOT_IV_SIZE + BVM_CHAPTER_SLOT_MAX_KEY_SIZE);
  if (slot_iv_key == NULL) {
    log_error("bvm_chapter_create: failed to create slot iv and key from key");
    goto chapter_generate_keys_fail_slot_iv_key;
  }

  bvm_key_t* slot_iv =
      bvm_key_create(slot_iv_key->data, BVM_CHAPTER_SLOT_IV_SIZE);
  if (slot_iv == NULL) {
    log_error("bvm_chapter_create: failed to create slot iv");
    goto chapter_generate_keys_fail_slot_iv;
  }

  bvm_key_t* slot_key =
      bvm_key_create(&slot_iv_key->data[BVM_CHAPTER_SLOT_IV_SIZE],
                     BVM_CHAPTER_SLOT_MAX_KEY_SIZE);
  if (slot_key == NULL) {
    log_error("bvm_chapter_create: failed to create slot key");
    goto chapter_generate_keys_fail_slot_key;
  }

  bvm_key_free(slot_iv_key);  // not needed anymore
  ch->page_key = page_key;
  ch->slot_iv = slot_iv;
  ch->slot_key = slot_key;
  *out_salt = salt;

  return BVM_OK;

chapter_generate_keys_fail_slot_key:
  bvm_key_free(slot_iv);
chapter_generate_keys_fail_slot_iv:
  bvm_key_free(slot_iv_key);
chapter_generate_keys_fail_slot_iv_key:
  bvm_key_free(salt);
chapter_generate_keys_fail_salt:
  bvm_key_free(page_key);
chapter_generate_keys_fail_page:
  return BVM_ERROR;
}

// helps to ensure args are passed in correct order
struct _bvm_chapter_open_generate_keys_args {
  const bvm_key_t* key;
  const bvm_key_t* salt;
  bvm_key_t** out_slot_key;
  bvm_key_t** out_slot_iv;
};

// internal function to generate chapter keys during decryption
static bvm_errcode_t _bvm_chapter_open_generate_keys(
    struct _bvm_chapter_open_generate_keys_args args) {
  const bvm_key_t* key = args.key;
  const bvm_key_t* salt = args.salt;
  bvm_key_t** out_slot_key = args.out_slot_key;
  bvm_key_t** out_slot_iv = args.out_slot_iv;

  *out_slot_key = NULL;
  *out_slot_iv = NULL;

  // generate slot key with iv, used to encrypt slot payload
  bvm_key_t* slot_iv_key = bvm_key_create_argon2id(
      BVM_CHAPTER_SLOT_ARGON2_DEFAULT_ITERATIONS,
      BVM_CHAPTER_SLOT_ARGON2_DEFAULT_MEMORY,
      BVM_CHAPTER_SLOT_ARGON2_DEFAULT_PARALLELISM, key->data, key->size,
      salt->data, salt->size,
      BVM_CHAPTER_SLOT_IV_SIZE + BVM_CHAPTER_SLOT_MAX_KEY_SIZE);
  if (slot_iv_key == NULL) {
    log_error("failed to create slot iv and key from key");
    goto chapter_open_generate_keys_fail_argon;
  }

  bvm_key_t* slot_iv =
      bvm_key_create(slot_iv_key->data, BVM_CHAPTER_SLOT_IV_SIZE);
  if (slot_iv == NULL) {
    log_error("bvm_chapter_create: failed to create slot iv");
    goto chapter_open_generate_keys_fail_slot_iv;
  }

  bvm_key_t* slot_key =
      bvm_key_create(&slot_iv_key->data[BVM_CHAPTER_SLOT_IV_SIZE],
                     BVM_CHAPTER_SLOT_MAX_KEY_SIZE);
  if (slot_key == NULL) {
    log_error("bvm_chapter_create: failed to create slot key");
    goto chapter_open_generate_keys_fail_slot_key;
  }

  bvm_key_free(slot_iv_key);  // not needed anymore
  *out_slot_key = slot_key;
  *out_slot_iv = slot_iv;

  return BVM_OK;

chapter_open_generate_keys_fail_slot_key:
  bvm_key_free(slot_iv);
chapter_open_generate_keys_fail_slot_iv:
  bvm_key_free(slot_iv_key);
chapter_open_generate_keys_fail_argon:
  return BVM_ERROR;
}

// this struct helps to ensure keys are passed in the correct order
struct _bvm_chapter_slot_keys {
  const bvm_key_t* slot_key;
  const bvm_key_t* slot_iv;
};

static gcry_error_t _bvm_chapter_slot_get_cipher_handle(
    const struct _bvm_chapter_slot_keys keys, gcry_cipher_hd_t* hd) {
  // TODO: fix, this is hard coded for now, get from chapter later
  int cipher = GCRY_CIPHER_TWOFISH;
  int mode = GCRY_CIPHER_MODE_XTS;
  gcry_error_t err;

  const bvm_key_t* slot_key = keys.slot_key;
  const bvm_key_t* slot_iv = keys.slot_iv;

  err = gcry_cipher_open(hd, cipher, mode, 0);
  if (err != GPG_ERR_NO_ERROR) {
    log_error("failed to open cipher with cipher=%d, mode=%i, err=%s/%s",
              cipher, mode, gcry_strsource(err), gcry_strerror(err));
    return err;
  }

  size_t ksize = gcry_cipher_get_algo_keylen(cipher);
  if (ksize > slot_key->size) {
    log_error("slot key too small for cipher key of %lu", ksize);
    goto chapter_slot_get_cipher_handle_fail;
  }

  err = gcry_cipher_setkey(*hd, slot_key->data, ksize);
  if (err != GPG_ERR_NO_ERROR) {
    log_error(
        "failed to set key with keysize=%lu, cipher=%d, mode=%i, err=%s/%s",
        slot_key->size, cipher, mode, gcry_strsource(err), gcry_strerror(err));
    goto chapter_slot_get_cipher_handle_fail;
  }

  err = gcry_cipher_setiv(*hd, slot_iv->data, slot_iv->size);
  if (err != GPG_ERR_NO_ERROR) {
    log_error("failed to set iv with cipher=%d, mode=%i, err=%s/%s", cipher,
              mode, gcry_strsource(err), gcry_strerror(err));
    goto chapter_slot_get_cipher_handle_fail;
  }

  return err;

chapter_slot_get_cipher_handle_fail:
  gcry_cipher_close(*hd);
  return err;
}

bvm_errcode_t bvm_chapter_slot_encrypt(const bvm_chapter_t* chapter,
                                       uint8_t* out, size_t outsize,
                                       const uint8_t* in, size_t insize) {
  gcry_cipher_hd_t hd;
  gcry_error_t err = GPG_ERR_NO_ERROR;

  err = _bvm_chapter_slot_get_cipher_handle(
      (struct _bvm_chapter_slot_keys){.slot_key = chapter->slot_key,
                                      .slot_iv = chapter->slot_iv},
      &hd);
  if (err != GPG_ERR_NO_ERROR) {
    return BVM_ERROR_CHAPTER_ENCRYPT;
  }

  err = gcry_cipher_encrypt(hd, out, outsize, in, insize);
  if (err != GPG_ERR_NO_ERROR) {
    log_error("failed to encrypt with err=%s/%s", gcry_strsource(err),
              gcry_strerror(err));
    goto chapter_slot_encrypt_fail_encrypt;
  }

  gcry_cipher_close(hd);
  return BVM_OK;

chapter_slot_encrypt_fail_encrypt:
  gcry_cipher_close(hd);
  return BVM_ERROR_CHAPTER_ENCRYPT;
}

bvm_errcode_t bvm_chapter_slot_decrypt(const bvm_key_t* slot_key,
                                       const bvm_key_t* slot_iv, uint8_t* out,
                                       size_t outsize, const uint8_t* in,
                                       size_t insize) {
  gcry_cipher_hd_t hd;
  gcry_error_t err = GPG_ERR_NO_ERROR;

  err = _bvm_chapter_slot_get_cipher_handle(
      (struct _bvm_chapter_slot_keys){.slot_key = slot_key, .slot_iv = slot_iv},
      &hd);
  if (err != GPG_ERR_NO_ERROR) {
    return BVM_ERROR_CHAPTER_DECRYPT;
  }

  err = gcry_cipher_decrypt(hd, out, outsize, in, insize);
  if (err != GPG_ERR_NO_ERROR) {
    log_error("failed to decrypt with err=%s/%s", gcry_strsource(err),
              gcry_strerror(err));
    goto chapter_slot_encrypt_fail_decrypt;
  }

  gcry_cipher_close(hd);
  return BVM_OK;

chapter_slot_encrypt_fail_decrypt:
  gcry_cipher_close(hd);
  return BVM_ERROR_CHAPTER_DECRYPT;
}

bvm_chapter_t* bvm_chapter_create_key(bvm_book_t* book, const bvm_key_t* key,
                                      size_t total_extents) {
  if (book == NULL) {
    log_error("bvm_chapter_create: book must not be null");
    return NULL;
  }

  bvm_dev_t* dev = bvm_book_get_dev(book);
  if (dev == NULL) {
    log_error("bvm_chapter_create: failed to get device from book");
    return NULL;
  }

  if (key == NULL) {
    log_error("bvm_chapter_create: key must not be null");
    return NULL;
  }

  if (bvm_book_get_chapters_free(book) < 1) {
    log_error(
        "bvm_chapter_create: not enough chapters free in book for new chapter");
    return NULL;
  }

  uint8_t slot = 0;
  if (bvm_book_get_random_free_slot(book, &slot) != BVM_OK) {
    log_error("bvm_chapter_create: failed to allocate random slot for chapter");
    return NULL;
  }

  uint64_t* extents = (uint64_t*)gcry_calloc(total_extents, sizeof(uint64_t));
  if (extents == NULL) {
    log_error("bvm_chapter_create: failed to allocate memory for extents");
    return NULL;
  }

  bvm_errcode_t err =
      bvm_book_extent_alloc_random(book, total_extents, extents);
  if (err != BVM_OK) {
    log_error("bvm_chapter_create: %s", bvm_strerror(err));
    goto chapter_create_key_fail_extent_alloc_random;
  }

  // create the chapter object
  bvm_chapter_t* ch = (bvm_chapter_t*)gcry_calloc(1, sizeof(bvm_chapter_t));
  if (ch == NULL) {
    log_error("bvm_chapter_create: failed to allocate memory for chapter");
    goto chapter_create_key_fail_alloc_chapter;
  }

  // set variables
  ch->book = book;
  ch->block_size = BVM_CHAPTER_DEFAULT_BLOCK_SIZE;
  ch->extents = extents;
  ch->total_extents = total_extents;
  book->chapters[slot] = ch;

  // generate keys and salt
  bvm_key_t* salt = NULL;
  if (_bvm_chapter_create_generate_keys(key, ch, &salt) != BVM_OK) {
    goto chapter_create_key_fail_generate_keys;
  }

  // write salt
  // NOTE: should not be changed as password generation requires this
  size_t offset = bvm_chapter_slot_get_offset(slot);
  if (bvm_dev_write(dev, salt->data, salt->size, offset) !=
      (ssize_t)salt->size) {
    log_error("bvm_chapter_create: failed to write salt to device");
    goto chapter_create_key_fail_write_salt;
  }
  offset += salt->size;

  // cleanup uneeded keys
  bvm_key_free(salt);

  return ch;

chapter_create_key_fail_write_salt:
  bvm_key_free(salt);
chapter_create_key_fail_generate_keys:
  bvm_chapter_close(ch);
chapter_create_key_fail_alloc_chapter:
  bvm_book_extent_free(book, total_extents, extents);
chapter_create_key_fail_extent_alloc_random:
  gcry_free(extents);

  return NULL;
}

bvm_errcode_t bvm_chapter_serialize(bvm_chapter_t* chapter, uint8_t** outbuf,
                                    size_t* outsize) {
  *outbuf = NULL;
  *outsize = 0;

  bool res;
  cbor_item_t* root = cbor_new_definite_map(2);
  if (root == NULL) {
    log_error("failed to create empty map");
    return BVM_ERROR_CHAPTER_SERIALIZE;
  }

  // extent serialize
  if (chapter->extents != NULL && chapter->total_extents > 0) {
    cbor_item_t* extent_array = cbor_new_definite_array(chapter->total_extents);
    if (extent_array == NULL) {
      log_error("failed to create empty extent array");
      goto chapter_serialize_fail_build;
    }

    for (size_t i = 0; i < chapter->total_extents; i++) {
      cbor_item_t* block = cbor_build_uint64(chapter->extents[i]);
      if (block == NULL) {
        log_error("failed to create uint64_t for block");
        cbor_decref(&extent_array);
        goto chapter_serialize_fail_build;
      }

      res = cbor_array_push(extent_array, cbor_move(block));
      if (!res) {
        cbor_decref(&extent_array);
        goto chapter_serialize_fail_build;
      }
    }

    cbor_item_t* key = cbor_build_uint8(BVM_CHAPTER_CBOR_EXTENT_KEY);
    res = cbor_map_add(root,
                       (struct cbor_pair){.key = cbor_move(key),
                                          .value = cbor_move(extent_array)});
    if (!res) {
      log_error("failed to add extents to map");
      goto chapter_serialize_fail_build;
    }
  }

  // key serialize
  bvm_key_t* page_key = chapter->page_key;
  if (page_key != NULL && page_key->size > 0) {
    cbor_item_t* data = cbor_build_bytestring(page_key->data, page_key->size);
    if (data == NULL) {
      log_error("failed to serialize key data");
      goto chapter_serialize_fail_build;
    }
    cbor_item_t* key = cbor_build_uint8(BVM_CHAPTER_CBOR_PAGE_KEY_KEY);
    res = cbor_map_add(root, (struct cbor_pair){.key = cbor_move(key),
                                                .value = cbor_move(data)});
    if (!res) {
      log_error("failed to add key to map");
      goto chapter_serialize_fail_build;
    }
  }

  // big enough for hash and cbor
  const size_t buffer_size = BVM_CHAPTER_SLOT_PAYLOAD_SIZE;
  uint8_t* buffer = gcry_calloc(1, buffer_size);

  // serialize into buffer after hash
  const size_t cbor_size = BVM_CHAPTER_SLOT_CBOR_SIZE;
  size_t length =
      cbor_serialize(root, &buffer[BVM_CHAPTER_SLOT_HASH_SIZE], cbor_size);
  if (length > cbor_size) {
    log_error("generated cbor data is too large");
    gcry_free(buffer);
    goto chapter_serialize_fail_buffer;
  }

  // hash buffer and store in start of buffer
  gcry_md_hash_buffer(GCRY_MD_SHA256, buffer,
                      &buffer[BVM_CHAPTER_SLOT_HASH_SIZE], cbor_size);

  cbor_decref(&root);
  *outbuf = buffer;
  *outsize = buffer_size;

  return BVM_OK;

chapter_serialize_fail_buffer:
  gcry_free(buffer);
chapter_serialize_fail_build:
  cbor_decref(&root);
  return BVM_ERROR_CHAPTER_SERIALIZE;
}

bvm_errcode_t bvm_chapter_deserialize(bvm_chapter_t* ch, const uint8_t* in,
                                      size_t insize) {
  if (ch->book == NULL) {
    log_error("chapter->book must not be null");
    return BVM_ERROR;
  }

  struct cbor_load_result result;
  cbor_item_t* root = cbor_load(in, insize, &result);
  if (root == NULL) {
    log_error("failed to load cbor");
    goto chapter_deserialize_fail;
  }

  if (!cbor_isa_map(root)) {
    log_error("invalid cbor type");
    cbor_describe(root, stderr);
    goto chapter_deserialize_fail_build;
  }

  ch->block_size = BVM_CHAPTER_DEFAULT_BLOCK_SIZE;
  // ch->extents = extents;
  // ch->total_extents = total_extents;
  log_debug("map_size: %lu", cbor_map_size(root));
  struct cbor_pair* pairs = cbor_map_handle(root);
  for (size_t i = 0; i < cbor_map_size(root); i++) {
    const cbor_item_t* key = pairs[i].key;
    const cbor_item_t* value = pairs[i].value;
    if (!cbor_isa_uint(key)) {
      log_error("invalid key type for item[%lu]", i);
      continue;
    }
    log_debug("item[%lu].key = %lu", i, cbor_get_uint64(key));
    log_debug("item[%lu].value isa bytestring = %i", i,
              cbor_isa_bytestring(value));

    const uint8_t kv = cbor_get_uint8(key);

    if (kv == BVM_CHAPTER_CBOR_PAGE_KEY_KEY) {
      // load key
      if (!cbor_isa_bytestring(value)) {
        log_error("invalid type %lu for cbor page key, must be bytestring");
        goto chapter_deserialize_fail_build;
      }
      ch->page_key = bvm_key_create(cbor_bytestring_handle(value),
                                    cbor_bytestring_length(value));
    } else if (kv == BVM_CHAPTER_CBOR_EXTENT_KEY) {
      // load extents
      if (!cbor_isa_array(value)) {
        log_error("invalid type %lu for cbor extents array, must be array",
                  cbor_typeof(value));
        goto chapter_deserialize_fail_build;
      }

      ch->total_extents = cbor_array_size(value);
      ch->extents = (uint64_t*)gcry_calloc(ch->total_extents, sizeof(uint64_t));

      // load extents values
      for (size_t eai = 0; eai < ch->total_extents; eai++) {
        const cbor_item_t* ev = cbor_array_get(value, eai);
        if (!cbor_isa_uint(ev)) {
          log_error("invalid type %lu for cbor extent item, must be a uint",
                    cbor_typeof(ev));
          goto chapter_deserialize_fail_build;
        }

        // everything checks out, save the extent:w
        ch->extents[eai] = cbor_get_uint64(ev);
        bvm_book_extent_mark_allocated(ch->book, ch->extents[eai]);
      }
    } else {
      log_warn("unknown cbor key %lu, ignoring", kv);
    }
  }

  if (ch->page_key == NULL) {
    log_error("failed to load page_key for chapter from cbor");
  } else if (ch->extents == NULL) {
    log_error("failed to load extents for chapter from cbor");
  } else {
    // all checks out, lets GOOOO!!!
    cbor_decref(&root);
    return BVM_OK;
  }

  // well shit
  goto chapter_deserialize_fail_build;

chapter_deserialize_fail_build:
  cbor_decref(&root);
chapter_deserialize_fail:
  return BVM_ERROR_CHAPTER_DESERIALIZE;
}

bvm_errcode_t bvm_chapter_write_slot(bvm_chapter_t* chapter) {
  bvm_book_t* book = chapter->book;
  bvm_dev_t* dev = bvm_book_get_dev(book);
  int slot = bvm_chapter_get_slot(chapter);
  if (slot < 0) {
    return BVM_ERROR_CHAPTER_SERIALIZE;
  }

  ssize_t offset = bvm_chapter_slot_get_offset(slot);
  if (offset < 0) {
    return BVM_ERROR_CHAPTER_SERIALIZE;
  }

  // remember to skip region for salt
  offset += BVM_CHAPTER_SLOT_SALT_SIZE;

  uint8_t* buf = NULL;
  size_t bufsize = 0;
  bvm_errcode_t err = BVM_OK;

  // serialize
  if ((err = bvm_chapter_serialize(chapter, &buf, &bufsize)) != BVM_OK) {
    return err;
  }

  if (bufsize != BVM_CHAPTER_SLOT_PAYLOAD_SIZE) {
    log_error("invalid size (%lu) for chapter slot", bufsize);
    goto chapter_write_slot_fail;
  }

  // encrypt
  if ((err = bvm_chapter_slot_encrypt(chapter, buf, bufsize, NULL, 0)) !=
      BVM_OK) {
    log_error("failed to encrypt slot data");
    goto chapter_write_slot_fail;
  }

  // write
  ssize_t written = bvm_dev_write(dev, buf, bufsize, offset);
  if (written < 0 || bufsize != (size_t)written) {
    log_error("failed to write serialized chapter to slot");
    err = BVM_ERROR_DEVICE_IO;
    goto chapter_write_slot_fail;
  }

  // cleanup
  gcry_free(buf);

  return BVM_OK;

chapter_write_slot_fail:
  gcry_free(buf);
  return err;
}

bvm_chapter_t* bvm_chapter_slot_open_key(bvm_book_t* book, uint8_t slot,
                                         const bvm_key_t* key) {
  // skip already opened slots
  if (!bvm_book_chapter_slot_is_free(book, slot)) {
    return NULL;
  }

  bvm_dev_t* dev = bvm_book_get_dev(book);
  if (slot >= bvm_book_get_chapters_max()) {
    log_error("slot (%lu) is too invalid", slot);
    return NULL;
  }

  // load salt
  bvm_key_t* salt = bvm_key_create_zero(BVM_CHAPTER_SLOT_SALT_SIZE);
  if (salt == NULL) {
    goto chapter_slot_open_key_fail;
  }

  ssize_t offset = bvm_chapter_slot_get_offset(slot);
  ssize_t dread = 0;
  dread = bvm_dev_read(dev, salt->data, salt->size, offset);
  offset += salt->size;
  if (dread < 0 || salt->size != (size_t)dread) {
    goto chapter_slot_open_key_fail_gen_key;
  }

  // generate key from salt
  bvm_errcode_t err = BVM_OK;
  bvm_key_t* slot_key;
  bvm_key_t* slot_iv;
  struct _bvm_chapter_open_generate_keys_args args = {.key = key,
                                                      .salt = salt,
                                                      .out_slot_key = &slot_key,
                                                      .out_slot_iv = &slot_iv};
  err = _bvm_chapter_open_generate_keys(args);
  if (err != BVM_OK) {
    goto chapter_slot_open_key_fail_gen_key;
  }

  //  load payload and decrypt
  size_t bufsize = BVM_CHAPTER_SLOT_PAYLOAD_SIZE;
  uint8_t* buf = gcry_calloc(1, bufsize);
  if (buf == NULL) {
    log_error("failed to allocate buffer for slot payload");
    goto chapter_slot_open_key_fail_alloc_buf;
  }

  // read slot payload
  dread = bvm_dev_read(dev, buf, bufsize, offset);
  if (dread < 0 || bufsize != (size_t)dread) {
    goto chapter_slot_open_key_fail_read_payload;
  }

  // decrypt payload
  err = bvm_chapter_slot_decrypt(slot_key, slot_iv, buf, bufsize, NULL, 0);
  if (err != BVM_OK) {
    log_error("failed to decrypt slot payload");
    goto chapter_slot_open_key_fail_read_payload;
  }

  // verify checksum
  do {
    uint8_t hash[BVM_CHAPTER_SLOT_HASH_SIZE];
    gcry_md_hash_buffer(GCRY_MD_SHA256, hash, &buf[BVM_CHAPTER_SLOT_HASH_SIZE],
                        BVM_CHAPTER_SLOT_CBOR_SIZE);
    if (memcmp(buf, hash, BVM_CHAPTER_SLOT_HASH_SIZE) != 0) {
      log_error("slot payload checksum mismatch");
      goto chapter_slot_open_key_fail_read_payload;
    }
  } while (0);

  // create the chapter object
  bvm_chapter_t* ch = (bvm_chapter_t*)gcry_calloc(1, sizeof(bvm_chapter_t));
  if (ch == NULL) {
    log_error("failed to allocate memory for chapter");
    goto chapter_slot_open_fail_chapter_create;
  }

  // set variables
  ch->book = book;
  book->chapters[slot] = ch;

  // load cbor
  err = bvm_chapter_deserialize(ch, &buf[BVM_CHAPTER_SLOT_HASH_SIZE],
                                BVM_CHAPTER_SLOT_CBOR_SIZE);
  if (err != BVM_OK) {
    goto chapter_slot_open_fail_chapter_create;
  }

  // load chapter

  return ch;

chapter_slot_open_fail_chapter_create:
  bvm_chapter_close(ch);
chapter_slot_open_key_fail_read_payload:
  gcry_free(buf);
chapter_slot_open_key_fail_alloc_buf:
  bvm_key_free(slot_key);
  bvm_key_free(slot_iv);
chapter_slot_open_key_fail_gen_key:
  bvm_key_free(salt);
chapter_slot_open_key_fail:
  return NULL;
}

bvm_chapter_t* bvm_chapter_open_key(bvm_book_t* book, const bvm_key_t* key) {
  for (int i = 0; i < bvm_book_get_chapters_max(); i++) {
    bvm_chapter_t* chapter = bvm_chapter_slot_open_key(book, i, key);
    if (chapter != NULL) {
      return chapter;
    }
  }
  return NULL;
}

void bvm_chapter_close(bvm_chapter_t* chapter) {
  if (chapter == NULL) {
    return;
  }

  bvm_book_t* book = chapter->book;
  int slot = bvm_chapter_get_slot(chapter);

  if (chapter->slot_key != NULL) {
    bvm_key_free(chapter->slot_key);
  }

  if (chapter->page_key != NULL) {
    bvm_key_free(chapter->page_key);
  }

  if (chapter->extents != NULL) {
    bvm_book_extent_free(book, chapter->total_extents, chapter->extents);
    gcry_free(chapter->extents);
  }

  gcry_free(chapter);

  if (slot > 0 && slot < bvm_book_get_chapters_max() && book != NULL) {
    book->chapters[slot] = NULL;
  }
}

size_t bvm_chapter_get_size(const bvm_chapter_t* chapter) {
  return chapter->total_extents * BVM_EXTENT_SIZE;
}

int bvm_chapter_get_slot(const bvm_chapter_t* chapter) {
  if (chapter == NULL || chapter->book == NULL) {
    return -1;
  }

  const bvm_book_t* book = chapter->book;
  for (uint8_t i = 0; i < BVM_BOOK_CHAPTERS_MAX; i++) {
    if (book->chapters[i] == chapter) {
      return i;
    }
  }
  return -1;
}

bvm_errcode_t bvm_chapter_resize(bvm_chapter_t* chapter, size_t total_extents) {
  if (chapter == NULL) {
    log_error("bvm_chapter_resize: chapter is null");
    return BVM_ERROR;
  }

  size_t current_size = chapter->total_extents;
  if (current_size == total_extents) {
    return BVM_OK;
  }

  if (current_size > total_extents) {  // shrink
    size_t diff = current_size - total_extents;
    (void)diff;  // TODO
    return BVM_OK;
  }

  return BVM_OK;
}
