/* Copyright 2021 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <gcrypt.h>
#include <limits.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stddef.h>

#include "bvm/bvm.h"
#include "cmocka.h"
#include "log.h"

static void test_bvm_static_values(void** state) {
  (void)state; /* unused */
  // test static values
  assert_int_equal(BVM_BOOK_CHAPTERS_MAX, 16);
  assert_in_range(BVM_HEADER_SIZE, BVM_MAGIC_HEADER_SIZE, BVM_EXTENT_SIZE);
  assert_int_not_equal(BVM_MAGIC_HEADER_SIZE, 0);
  assert_int_not_equal(BVM_EXTENT_SIZE, 0);
  assert_int_equal(BVM_DEV_MIN_SIZE, BVM_EXTENT_SIZE * BVM_DEV_MIN_EXTENTS);
  assert_int_equal(BVM_DEV_MIN_EXTENTS, 1);

  assert_int_not_equal(BVM_CHAPTER_SLOT_SALT_SIZE, 0);
  assert_in_range(BVM_CHAPTER_SLOT_SALT_SIZE, 1, BVM_CHAPTER_SLOT_SIZE);
  assert_in_range(BVM_CHAPTER_SLOT_PAYLOAD_SIZE, 1, BVM_CHAPTER_SLOT_SIZE);
  assert_int_equal(BVM_CHAPTER_SLOT_SALT_SIZE + BVM_CHAPTER_SLOT_PAYLOAD_SIZE,
                   BVM_CHAPTER_SLOT_SIZE);
  assert_int_equal(BVM_CHAPTER_SLOT_IV_SIZE, 16);

  size_t blklen = gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
  assert_int_equal(blklen, 16);
  assert_int_equal(BVM_EXTENT_SIZE % blklen, 0);
  assert_int_not_equal(BVM_EXTENT_SIZE, 0);
  assert_int_equal(BVM_CHAPTER_SLOT_SIZE % blklen, 0);
  assert_int_not_equal(BVM_CHAPTER_SLOT_SIZE, 0);
}

static void test_bvm_strerror(void** state) {
  (void)state; /* unused */
  assert_int_equal(BVM_OK, 0);
  assert_null(bvm_strerror(BVM_OK));
  assert_non_null(bvm_strerror(BVM_ERROR));
}

static void test_bvm_init_success(void** state) {
  (void)state; /* unused */
  assert_true(bvm_gcrypt_init());
  assert_true(bvm_init());
}

static void test_bvm_key_create_random(void** state) {
  (void)state; /* unused */
  size_t size = 256 / 8;
  bvm_key_t* key = bvm_key_create_random(size);
  assert_non_null(key);
  assert_non_null(key->data);
  assert_int_equal(key->size, size);
  bvm_key_free(key);
}

static void test_gcrypt_xts(void** state) {
  (void)state; /* unused */

  gcry_cipher_hd_t hd;
  gcry_error_t err = 0;
  err = gcry_cipher_open(&hd, GCRY_CIPHER_TWOFISH, GCRY_CIPHER_MODE_XTS, 0);
  if (err) {
    fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
            gcry_strerror(err));
  }
  assert_int_equal(err, GPG_ERR_NO_ERROR);
  uint8_t data[16];
  memset(data, 0, sizeof(data));

  uint8_t key[256 / 8];
  memset(key, 0, sizeof(key));
  err = gcry_cipher_setkey(hd, key, sizeof(key));
  assert_int_equal(err, GPG_ERR_NO_ERROR);

  uint64_t iv[2];
  memset(iv, 0, sizeof(iv));
  err = gcry_cipher_setiv(hd, iv, sizeof(iv));
  assert_int_equal(err, GPG_ERR_NO_ERROR);

  size_t bsize = 16 * 5;
  uint8_t out[bsize];
  uint8_t in[bsize];
  memset(out, 0, sizeof(out));
  memset(in, 0, sizeof(in));
  err = gcry_cipher_encrypt(hd, out, sizeof(out), in, sizeof(in));
  if (err) {
    fprintf(stderr, "Failure: %s/%s\n", gcry_strsource(err),
            gcry_strerror(err));
  }

  assert_int_equal(err, GPG_ERR_NO_ERROR);

  for (size_t i = 0; i < sizeof(in); i++) {
    assert_int_equal(in[i], 0);
    /*assert_int_not_equal(out[i], 0);*/
  }
  assert_memory_not_equal(in, out, sizeof(in));

  gcry_cipher_close(hd);
}

static void test_bvm_bitmap(void** state) {
  (void)state; /* unused */
  size_t nbits = 20;
  bvm_bitmap_t* bitmap = bvm_bitmap_create(nbits);

  assert_non_null(bitmap);
  assert_non_null(bitmap->bitarray);
  assert_int_equal(nbits, bitmap->nbits);
  assert_int_equal(bvm_bitmap_size_bytes(bitmap), ((nbits + 8 - 1) / CHAR_BIT));
  assert_int_equal(bvm_bitmap_cardinality(bitmap), 0);

  // default all unset
  for (size_t i = 0; i < bitmap->nbits; i++) {
    assert_int_equal(bvm_bitmap_bit_test(bitmap, i), 0);
  }

  // change 1
  size_t changed = 5;
  bvm_bitmap_bit_set(bitmap, changed);
  assert_int_equal(bvm_bitmap_cardinality(bitmap), 1);
  for (size_t i = 0; i < bitmap->nbits; i++) {
    assert_int_equal(bvm_bitmap_bit_test(bitmap, i), i == changed);
  }

  // change all
  for (size_t i = 0; i < bitmap->nbits; i++) {
    bvm_bitmap_bit_set(bitmap, i);
    assert_int_equal(bvm_bitmap_bit_test(bitmap, i), 1);
  }
  assert_int_equal(bvm_bitmap_cardinality(bitmap), bitmap->nbits);

  // clear all
  for (size_t i = 0; i < bitmap->nbits; i++) {
    bvm_bitmap_bit_clear(bitmap, i);
    assert_int_equal(bvm_bitmap_bit_test(bitmap, i), 0);
  }
  assert_int_equal(bvm_bitmap_cardinality(bitmap), 0);

  // bounds checking
  assert_int_equal(bvm_bitmap_bit_test(bitmap, nbits), -1);
  assert_int_equal(bvm_bitmap_bit_test(bitmap, nbits + 100), -1);

  // cleanup
  bvm_bitmap_free(bitmap);
  bitmap = NULL;

  //*** test big bitmap
  // extents in a 8TB drive with 32MB extent size, 1 bit per extent
  nbits = (8ULL * 1024 * 1024 * 1024 * 1024) / (32 * 1024 * 1024);
  bitmap = bvm_bitmap_create(nbits);
  assert_non_null(bitmap);
  assert_non_null(bitmap->bitarray);
  assert_int_equal(bitmap->nbits, nbits);
  assert_int_equal(bvm_bitmap_cardinality(bitmap), 0);

  // check a "random" value change
  changed = 1024ULL * 5;
  assert_in_range(changed, 0, nbits - 1);
  bvm_bitmap_bit_set(bitmap, changed);
  assert_int_equal(bvm_bitmap_cardinality(bitmap), 1);
  for (size_t i = 0; i < bitmap->nbits; i++) {
    assert_int_equal(bvm_bitmap_bit_test(bitmap, i), i == changed);
  }

  // cleanup
  bvm_bitmap_free(bitmap);
  bitmap = NULL;
}

static void test_bvm_dev_mem(void** state) {
  (void)state; /* unused */
  size_t bsize = 1024 * 1024 * 32 * 2;
  uint8_t* buf = (uint8_t*)calloc(1, bsize);
  assert_non_null(buf);

  bvm_dev_t* md = bvm_dev_memopen(buf, bsize);
  assert_non_null(md);
  assert_non_null(md->user);

  // test name
  assert_string_equal(BVM_DEV_MEM_NAME, "bvm_dev_mem");
  assert_string_equal(bvm_dev_get_name(md), BVM_DEV_MEM_NAME);
  assert_ptr_equal(bvm_dev_get_name(md), BVM_DEV_MEM_NAME);

  // test get_size
  assert_int_equal(bvm_dev_get_size(md), bsize);
  assert_int_equal(bvm_dev_get_blocksize(md), 4096);

  // test write
  size_t offset = 3;
  uint8_t expected[] = {3, 2, 1};
  assert_int_equal(bvm_dev_write(md, expected, sizeof(expected), offset),
                   sizeof(expected));
  assert_memory_equal(&buf[offset], expected, sizeof(expected));

  // test read data
  uint8_t tbuf[3];
  memset(tbuf, 0, sizeof(tbuf));
  assert_int_equal(bvm_dev_read(md, tbuf, sizeof(tbuf), offset), sizeof(tbuf));
  assert_memory_equal(tbuf, expected, sizeof(tbuf));

  for (size_t i = 0; i < sizeof(expected) / sizeof(uint8_t); i++) {
    expected[i] = i + 1;
  }
  assert_memory_not_equal(&buf[offset], expected, sizeof(expected));
  assert_int_equal(bvm_dev_write(md, expected, sizeof(expected), offset),
                   sizeof(expected));

  // test flush
  assert_int_equal(bvm_dev_flush(md), BVM_OK);

  // close is OK
  assert_int_equal(bvm_dev_close(md), BVM_OK);

  // cleanup
  free(buf);
}

static void test_bvm_dev_mem_alloc(void** state) {
  (void)state; /* unused */
  // test managed
  size_t bsize = 32 * 1024 * 1024;
  bvm_dev_t* dev = bvm_dev_memopen(NULL, bsize);
  assert_non_null(dev);
  assert_int_equal(bvm_dev_get_size(dev), bsize);
  assert_int_equal(bvm_dev_close(dev), BVM_OK);
}

static void test_bvm_book_create_too_small(void** state) {
  (void)state; /* unused */
  // two extents, 1 for header
  size_t bsize = 1024 * 1024 * 32 - 1;
  uint8_t* buf = (uint8_t*)calloc(1, bsize);

  // should return null because device should be too small
  bvm_book_t* book = bvm_book_memopen(buf, bsize);
  assert_null(book);

  // cleanup
  free(buf);
}

static void test_bvm_book_create(void** state) {
  (void)state; /* unused */

  // static checks
  // extents divisible by 4k block size
  assert_int_equal(BVM_EXTENT_SIZE % 4096, 0);

  // two extents, 1 for header
  size_t total_extents = 2;
  size_t dsize =
      (total_extents * BVM_EXTENT_SIZE) + 4096;  // 4096 to test extra space

  // open book
  bvm_book_t* book = bvm_book_memopen(NULL, dsize);
  assert_non_null(book);
  assert_non_null(book->dev);

  // auxillary functions
  bvm_dev_t* dev = bvm_book_get_dev(book);
  assert_ptr_equal(book->dev, dev);
  assert_ptr_equal(bvm_dev_get_name(dev), BVM_DEV_MEM_NAME);
  assert_int_equal(bvm_dev_get_size(dev), dsize);
  assert_int_equal(bvm_book_get_extent_size(book), BVM_EXTENT_SIZE);
  assert_int_equal(bvm_book_get_extents_total(book), total_extents);
  assert_int_equal(bvm_book_get_extents_free(book),
                   total_extents - BVM_HEADER_EXTENTS_REQUIRED);

  // magic header
  ssize_t read = 0;
  char buf[4096];
  memset(buf, 0, sizeof(buf));

  assert_false(bvm_book_magic_exists(book));
  assert_int_equal(bvm_book_magic_add(book), BVM_OK);
  assert_true(bvm_book_magic_exists(book));
  read = bvm_dev_read(dev, buf, BVM_MAGIC_HEADER_SIZE, 0);
  assert_int_equal(read, BVM_MAGIC_HEADER_SIZE);
  assert_memory_equal(buf, BVM_MAGIC_HEADER, BVM_MAGIC_HEADER_SIZE);

  char expected[sizeof(buf)];
  for (size_t i = 0; i < dsize; i += sizeof(buf)) {
    memset(expected, 0, sizeof(expected));
    if (i == 0) {  // magic header
      memcpy(expected, BVM_MAGIC_HEADER, BVM_MAGIC_HEADER_SIZE);
    }

    size_t expected_read = sizeof(buf);
    if ((expected_read + i) > dsize) {
      expected_read = dsize - i;  // read the tail end
    }

    read = bvm_dev_read(dev, buf, expected_read, i);
    assert_int_equal(read, expected_read);
    assert_memory_equal(buf, expected, expected_read);
  }

  memset(expected, 0, sizeof(expected));
  memset(buf, 0, sizeof(buf));
  assert_int_equal(bvm_book_magic_remove(book), BVM_OK);
  read = bvm_dev_read(dev, buf, BVM_MAGIC_HEADER_SIZE, 0);
  assert_int_equal(read, BVM_MAGIC_HEADER_SIZE);
  assert_memory_equal(buf, expected, sizeof(buf));

  // chapter sizes
  assert_in_range(BVM_BOOK_CHAPTERS_MAX, 1, UINT8_MAX);
  assert_int_equal(bvm_book_get_chapters_max(), BVM_BOOK_CHAPTERS_MAX);
  assert_int_equal(bvm_book_get_chapters_total(book), 0);
  assert_int_equal(bvm_book_get_chapters_free(book), BVM_BOOK_CHAPTERS_MAX);
  for (uint8_t i = 0; i < bvm_book_get_chapters_max(); i++) {
    assert_true(bvm_book_chapter_slot_is_free(book, i));
  }

  // cleanup
  bvm_book_close(book);
}

static void test_bvm_book_extent_allocation_tiny(void** state) {
  (void)state; /* unused */

  bvm_book_t* book = bvm_book_memopen(NULL, BVM_EXTENT_SIZE * 2);
  assert_non_null(book);
  assert_non_null(book->dev);
  assert_int_equal(bvm_book_get_extents_free(book), 1);

  // extent allocation
  uint64_t extents[8];

  memset(extents, 0, sizeof(extents));
  assert_int_equal(bvm_book_extent_alloc_random(book, 0, extents), BVM_OK);
  assert_int_equal(extents[0], 0);

  memset(extents, 0, sizeof(extents));
  assert_int_equal(bvm_book_extent_alloc_random(book, 100, extents),
                   BVM_ERROR_NO_EXTENT_SPACE);
  assert_int_equal(extents[0], 0);

  memset(extents, 0, sizeof(extents));
  assert_int_equal(bvm_book_extent_alloc_random(book, 1, extents), BVM_OK);
  assert_int_equal(extents[0], 1);  // only 1 extent to allocate, rest empty
  for (size_t i = 1; i < sizeof(extents) / sizeof(uint64_t); i++) {
    assert_int_equal(extents[i], 0);
  }
  assert_int_equal(bvm_book_get_extents_free(book), 0);

  // test extent free
  assert_int_equal(bvm_book_extent_free(book, 1, &extents[0]), BVM_OK);
  assert_int_equal(bvm_book_get_extents_free(book), 1);

  // cleanup
  bvm_book_close(book);
}

static void test_bvm_book_extent_allocation_small(void** state) {
  (void)state; /* unused */

  size_t total_extents = 10;
  size_t usable_extents = total_extents - 1;
  bvm_book_t* book = bvm_book_memopen(NULL, BVM_EXTENT_SIZE * total_extents);
  assert_non_null(book);
  assert_non_null(book->dev);
  assert_int_equal(bvm_book_get_extents_free(book), usable_extents);

  uint64_t extents[usable_extents];

  memset(extents, 0, sizeof(extents));
  assert_int_equal(bvm_book_extent_alloc_random(book, 0, extents), BVM_OK);
  assert_int_equal(extents[0], 0);

  memset(extents, 0, sizeof(extents));
  assert_int_equal(bvm_book_extent_alloc_random(book, 100, extents),
                   BVM_ERROR_NO_EXTENT_SPACE);
  assert_int_equal(extents[0], 0);

  memset(extents, 0, sizeof(extents));
  assert_int_equal(bvm_book_extent_alloc_random(book, 1, extents), BVM_OK);
  // only 1 extent to allocate, rest empty
  assert_in_range(extents[0], 1, usable_extents);
  for (size_t i = 1; i < sizeof(extents) / sizeof(uint64_t); i++) {
    assert_int_equal(extents[i], 0);  // rest extents unset
  }
  assert_int_equal(bvm_book_get_extents_free(book), usable_extents - 1);
  assert_int_equal(bvm_book_extent_free(book, 1, &extents[0]), BVM_OK);
  assert_int_equal(bvm_book_get_extents_free(book), usable_extents);

  // full allocation
  memset(extents, 0, sizeof(extents));
  assert_int_equal(bvm_book_extent_alloc_random(book, total_extents, extents),
                   BVM_ERROR_NO_EXTENT_SPACE);
  assert_int_equal(bvm_book_extent_alloc_random(book, usable_extents, extents),
                   BVM_OK);
  for (size_t i = 0; i < usable_extents; i++) {
    assert_in_range(extents[i], 1, usable_extents);
  }
  assert_int_equal(bvm_book_get_extents_free(book), 0);
  assert_int_equal(bvm_book_extent_free(book, 1, &extents[0]), BVM_OK);
  assert_int_equal(bvm_book_get_extents_free(book), 1);

  // freeing again shouldn't change anything
  assert_int_equal(bvm_book_extent_free(book, 1, &extents[0]), BVM_OK);
  assert_int_equal(bvm_book_get_extents_free(book), 1);

  // gradually freeing should increase size
  for (size_t i = 1; i < usable_extents; i++) {
    assert_int_equal(bvm_book_get_extents_free(book), i);
    assert_int_equal(bvm_book_extent_free(book, 1, &extents[i]), BVM_OK);
    assert_int_equal(bvm_book_get_extents_free(book), i + 1);
  }

  // cleanup
  bvm_book_close(book);
}

static void test_bvm_chapter_create_key(void** state) {
  (void)state; /* unused */

  // check slot offset math
  assert_int_equal(bvm_chapter_slot_get_offset(0), 256);
  assert_int_equal(bvm_chapter_slot_get_offset(1), 2097136 + 256);
  for (uint8_t i = 0; i < bvm_book_get_chapters_max(); i++) {
    assert_int_equal(bvm_chapter_slot_get_offset(i),
                     BVM_HEADER_SIZE + (i * BVM_CHAPTER_SLOT_SIZE));
  }

  size_t total_extents = 10;
  size_t usable_extents = total_extents - 1;
  bvm_book_t* book = bvm_book_memopen(NULL, BVM_EXTENT_SIZE * total_extents);

  assert_non_null(book);
  assert_non_null(book->dev);
  assert_int_equal(bvm_book_get_extents_free(book), usable_extents);

  bvm_key_t* key = bvm_key_create_random(256 / 8);
  assert_non_null(key);

  // check free slots randomly
  for (uint32_t i = 0; i < 1000; i++) {
    uint8_t slot = 0;
    assert_int_equal(bvm_book_get_random_free_slot(book, &slot), BVM_OK);
    assert_in_range(slot, 0, bvm_book_get_chapters_max() - 1);
  }

  // create chapter
  bvm_chapter_t* ch = bvm_chapter_create_key(book, key, usable_extents);
  assert_non_null(ch);

  uint8_t slot = bvm_chapter_get_slot(ch);
  assert_ptr_equal(ch->book, book);
  assert_in_range(slot, 0, bvm_book_get_chapters_max() - 1);
  assert_ptr_equal(book->chapters[slot], ch);
  assert_int_equal(bvm_chapter_get_size(ch), usable_extents * BVM_EXTENT_SIZE);
  assert_int_equal(bvm_book_get_extents_free(book), 0);

  // test slot writing
  bvm_dev_t* dev = bvm_book_get_dev(book);

  // clear slots, except for chapter slot
  do {
    assert_int_equal(bvm_book_magic_remove(book), BVM_OK);
    const size_t bufsize = BVM_CHAPTER_SLOT_SIZE;
    uint8_t* buf = calloc(1, bufsize);
    for (size_t i = 0; i < bvm_book_get_chapters_max(); i++) {
      if (i == slot) continue;
      const size_t offset = bvm_chapter_slot_get_offset(i);
      ssize_t written = bvm_dev_write(dev, buf, bufsize, offset);
      assert_int_equal(written, bufsize);
    }
    free(buf);
  } while (0);

  // write slot
  assert_int_equal(bvm_chapter_write_slot(ch), BVM_OK);

  // only this slot should have been written
  uint8_t* zerobuf = calloc(1, BVM_CHAPTER_SLOT_SIZE);
  for (size_t i = 0; i < bvm_book_get_chapters_max(); i++) {
    size_t offset = bvm_chapter_slot_get_offset(i);
    size_t bufsize = BVM_CHAPTER_SLOT_SIZE;
    uint8_t* buf = calloc(1, bufsize);
    ssize_t read = bvm_dev_read(dev, buf, bufsize, offset);
    assert_int_equal(read, BVM_CHAPTER_SLOT_SIZE);

    // buf data offsets
    size_t salt_offset = 0;
    size_t hash_offset = salt_offset + BVM_CHAPTER_SLOT_SALT_SIZE;
    size_t cbor_offset = hash_offset + BVM_CHAPTER_SLOT_HASH_SIZE;
    const size_t cbor_size = BVM_CHAPTER_SLOT_CBOR_SIZE;
    uint8_t hash_size = BVM_CHAPTER_SLOT_HASH_SIZE;

    if (i != slot) {
      assert_memory_equal(buf, zerobuf, bufsize);
    } else {
      assert_memory_not_equal(buf, zerobuf, bufsize);

      uint8_t* orig = calloc(1, BVM_CHAPTER_SLOT_PAYLOAD_SIZE);
      memcpy(orig, &buf[hash_offset], BVM_CHAPTER_SLOT_PAYLOAD_SIZE);

      // decrypt
      assert_int_equal(
          bvm_chapter_slot_decrypt(ch->slot_key, ch->slot_iv, &buf[hash_offset],
                                   BVM_CHAPTER_SLOT_PAYLOAD_SIZE, NULL, 0),
          BVM_OK);

      assert_memory_not_equal(orig, buf, BVM_CHAPTER_SLOT_PAYLOAD_SIZE);
      free(orig);

      // verify hash of data
      uint8_t hash[hash_size];
      gcry_md_hash_buffer(GCRY_MD_SHA256, hash, &buf[cbor_offset], cbor_size);

      assert_int_equal(BVM_CHAPTER_SLOT_HASH_SIZE, 256 / 8);
      assert_memory_equal(hash, &buf[hash_offset], hash_size);

      // already opened slot should return null
      assert_null(bvm_chapter_slot_open_key(book, slot, key));

      // store values
      size_t total_extents = ch->total_extents;
      uint64_t* extents = calloc(total_extents, sizeof(uint64_t));
      memcpy(extents, ch->extents, sizeof(uint64_t) * total_extents);

      // close and reopen with key
      bvm_chapter_close(ch);
      ch = bvm_chapter_slot_open_key(book, slot, key);
      assert_non_null(ch);

      assert_int_equal(ch->total_extents, total_extents);
      assert_memory_equal(ch->extents, extents,
                          sizeof(uint64_t) * total_extents);

      // cleanup
      free(extents);
    }
    free(buf);
  }
  free(zerobuf);

  // cleanup
  bvm_book_close(book);
}

int main(void) {
  const struct CMUnitTest tests[] = {
      cmocka_unit_test(test_bvm_static_values),
      cmocka_unit_test(test_bvm_strerror),
      cmocka_unit_test(test_bvm_init_success),
      cmocka_unit_test(test_bvm_key_create_random),
      cmocka_unit_test(test_bvm_bitmap),
      cmocka_unit_test(test_bvm_dev_mem),
      cmocka_unit_test(test_bvm_dev_mem_alloc),
      cmocka_unit_test(test_bvm_book_create_too_small),
      cmocka_unit_test(test_bvm_book_extent_allocation_tiny),
      cmocka_unit_test(test_bvm_book_extent_allocation_small),
      cmocka_unit_test(test_bvm_book_create),
      cmocka_unit_test(test_bvm_chapter_create_key),
      cmocka_unit_test(test_gcrypt_xts),
  };
  return cmocka_run_group_tests_name("libbvm", tests, NULL, NULL);
}
