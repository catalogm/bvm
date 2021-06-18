/* Copyright 2021 Kelvin Hammond <hammond.kelvin@gmail.com> */
#ifndef BVM_BVM_H
#define BVM_BVM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BVM_NEED_LIBGCRYPT_VERSION "1.9.2"
#define BVM_EXTENT_SIZE ((uint64_t)(32 * 1024 * 1024))
#define BVM_HEADER_EXTENTS_REQUIRED ((uint64_t)1)
#define BVM_DEV_MIN_EXTENTS BVM_HEADER_EXTENTS_REQUIRED
#define BVM_DEV_MIN_SIZE (BVM_EXTENT_SIZE * BVM_DEV_MIN_EXTENTS)

#define BVM_BOOK_CHAPTERS_MAX 16
#define BVM_CHAPTER_DEFAULT_BLOCK_SIZE 4096UL

// Magic + Meta header constants
#define BVM_MAGIC_HEADER_OFFSET 0
#define BVM_MAGIC_HEADER "BVM"
#define BVM_MAGIC_HEADER_SIZE 3UL
#define BVM_META_HEADER_SIZE 253UL
#define BVM_HEADER_SIZE (BVM_META_HEADER_SIZE + BVM_MAGIC_HEADER_SIZE)

// Chapter slot constants
#define BVM_CHAPTER_SLOT_SIZE \
  ((BVM_EXTENT_SIZE - BVM_META_HEADER_SIZE) / BVM_BOOK_CHAPTERS_MAX)
#define BVM_CHAPTER_SLOT_SALT_SIZE 128UL
#define BVM_CHAPTER_SLOT_PAYLOAD_SIZE \
  (BVM_CHAPTER_SLOT_SIZE - BVM_CHAPTER_SLOT_SALT_SIZE)

#define BVM_CHAPTER_SLOT_ARGON2_DEFAULT_ITERATIONS 9
#define BVM_CHAPTER_SLOT_ARGON2_DEFAULT_MEMORY (1 << 18)
#define BVM_CHAPTER_SLOT_ARGON2_DEFAULT_PARALLELISM 8

#define BVM_CHAPTER_SLOT_HASH_SIZE 32UL
#define BVM_CHAPTER_SLOT_CBOR_SIZE \
  (BVM_CHAPTER_SLOT_PAYLOAD_SIZE - BVM_CHAPTER_SLOT_HASH_SIZE)

#define BVM_CHAPTER_SLOT_IV_SIZE (128 / 8)
// 128 bit iv + 256 bit key * 3 (for algorithms) * 2 for XTS
#define BVM_CHAPTER_SLOT_MAX_KEY_SIZE ((256 / 8) * 3 * 2)

// CBOR map keys
typedef enum bvm_chapter_cbor_key_e {
  BVM_CHAPTER_CBOR_EXTENT_KEY = 0,
  BVM_CHAPTER_CBOR_PAGE_KEY_KEY = 1,
  BVM_CHAPTER_CBOR_ALGORITH_KEY = 2,
  BVM_CHAPTER_CBOR_STATUS_KEY = 3,
} bvm_chapter_cbor_key_t;

typedef struct bvm_key_s {
  uint8_t* data;
  size_t size;
} bvm_key_t;

typedef struct bvm_book_s bvm_book_t;

typedef struct bvm_dev_s bvm_dev_t;

typedef enum bvm_errcode_e {
  BVM_OK = 0,
  BVM_ERROR = -1,
  BVM_ERROR_EOF = -2,
  BVM_EOF = -2,
  BVM_ERROR_DEVICE_CLOSED = -3,
  BVM_ERROR_DEVICE_IO = -4,
  BVM_ERROR_NO_CHAPTERS_FREE = -5,
  BVM_ERROR_NO_EXTENT_SPACE = -6,
  BVM_ERROR_CHAPTER_SERIALIZE = -7,
  BVM_ERROR_CHAPTER_DESERIALIZE = -8,
  BVM_ERROR_CHAPTER_ENCRYPT = -9,
  BVM_ERROR_CHAPTER_DECRYPT = -10,
} bvm_errcode_t;

/* TODO: There are two block sizes
 * 1) Book Block Size, 32Mb used for allocation
 * 2) Chapter Block size, underlying device in a chapter, determines how much
 * data is encrypted, min 256 bytes
 */

/**
 * Dev operations implementation
 **/
typedef struct bvm_dev_ops_s {
  const char* name;
  size_t (*get_size)(bvm_dev_t* dev);
  ssize_t (*get_blocksize)(bvm_dev_t* dev);
  bvm_errcode_t (*close)(bvm_dev_t* dev);
  ssize_t (*read)(bvm_dev_t* dev, void* buf, size_t nbyte, size_t offset);
  ssize_t (*write)(bvm_dev_t* dev, const void* buf, size_t nbyte,
                   size_t offset);
  bvm_errcode_t (*flush)(bvm_dev_t* dev);
} bvm_dev_ops_t;

/** device constants **/
extern const char* const BVM_DEV_MEM_NAME;

typedef struct bvm_dev_s {
  bvm_dev_ops_t ops;
  void* user;
} bvm_dev_t;

typedef struct bvm_chapter_s {
  bvm_book_t* book;
  /* must be evenly divisible by extent_size
   * greater than or equal to 512
   * data is encrypted in these increments on disk */
  size_t block_size; /* sector = (extent * extent_size / block_size) */
  uint64_t* extents;
  size_t total_extents;

  bvm_key_t* slot_iv;   // slot payload iv
  bvm_key_t* slot_key;  // slot payload key
  bvm_key_t* page_key;  // content / data key
} bvm_chapter_t;

typedef struct bvm_bitmap_s {
  char* bitarray;
  size_t nbits;
} bvm_bitmap_t;

typedef struct bvm_book_s {
  uint64_t extent_size; /* default 32 Mb (1024^2 * 32) */
  bvm_dev_t* dev;
  bvm_bitmap_t* bitmap;
  bvm_chapter_t* chapters[BVM_BOOK_CHAPTERS_MAX];
} bvm_book_t;

/** error functions **/
const char* bvm_strerror(bvm_errcode_t err);

/** init functioons **/
bool bvm_gcrypt_init();
bool bvm_init();

/** bitmap functions **/
bvm_bitmap_t* bvm_bitmap_create(size_t nbits);
void bvm_bitmap_free(bvm_bitmap_t* bitmap);
size_t bvm_bitmap_size_bytes(const bvm_bitmap_t* bitmap);
void bvm_bitmap_printf(const bvm_bitmap_t* bitmap);
void bvm_bitmap_bit_set(bvm_bitmap_t* bitmap, size_t bit);
void bvm_bitmap_bit_clear(bvm_bitmap_t* bitmap, size_t bit);

/**
 * Checks if bit is set
 * @param bitmap bitmap
 * @param[in] bit the bit to set
 * @return -1 on err, 0 if unset, 1 if set
 **/
int bvm_bitmap_bit_test(const bvm_bitmap_t* bitmap, size_t bit);
size_t bvm_bitmap_cardinality(const bvm_bitmap_t* bitmap);

/** key functions **/
bvm_key_t* bvm_key_create_zero(size_t size);
bvm_key_t* bvm_key_create(const uint8_t* data, size_t size);
bvm_key_t* bvm_key_dup(const bvm_key_t* key);
bvm_key_t* bvm_key_create_random(size_t size);
void bvm_key_free(bvm_key_t* key);

/**
 * Create a key using argon2id algorithm
 *
 * @param t_cost time cost, sets the number of iterations
 * @param m_cost memory cost, sets the memory usage of 2^N KiB
 * @param parallelism sets parallelism to N threads
 * @param pwd,pwdlen password and length
 * @param salt,saltlen salt and length
 * @param size size of key to create
 * @return derived key or NULL on error
 **/
bvm_key_t* bvm_key_create_argon2id(const uint32_t t_cost, const uint32_t m_cost,
                                   const uint32_t parallelism, const void* pwd,
                                   const size_t pwdlen, const void* salt,
                                   const size_t saltlen, const size_t size);

/** device functions **/
bvm_dev_t* bvm_dev_create(bvm_dev_ops_t ops, void* user);
const char* bvm_dev_get_name(bvm_dev_t* dev);
size_t bvm_dev_get_size(bvm_dev_t* dev);
ssize_t bvm_dev_get_blocksize(bvm_dev_t* dev);

/**
 * Closes the device and free's it
 *
 * dev should not be used after this call.
 */
bvm_errcode_t bvm_dev_close(bvm_dev_t* dev);
ssize_t bvm_dev_read(bvm_dev_t* dev, void* buf, size_t nbyte, size_t offset);
ssize_t bvm_dev_write(bvm_dev_t* dev, const void* buf, size_t nbyte,
                      size_t offset);
bvm_errcode_t bvm_dev_flush(bvm_dev_t* dev);

/** memory device functions **/

/**
 * Open a device with data stored in memory
 *
 * If mem is NULL and size > 0 memory will be allocated for the device and freed
 * on close.
 *
 * @param[in] mem memory used, if NULL memory will be allocated
 * @param[in] size size of memory buffer
 * @return new device or NULL on error
 */
bvm_dev_t* bvm_dev_memopen(void* mem, size_t size);

/** book functions **/
bvm_book_t* bvm_book_open_dev(bvm_dev_t* dev);
bvm_book_t* bvm_book_memopen(void* mem, size_t size);
void bvm_book_close(bvm_book_t* book);

bvm_dev_t* bvm_book_get_dev(bvm_book_t* book);
size_t bvm_book_get_size(bvm_book_t* book);
size_t bvm_book_get_extent_size(const bvm_book_t* book);
size_t bvm_book_get_extents_total(bvm_book_t* book);
size_t bvm_book_get_extents_free(bvm_book_t* book);

bvm_errcode_t bvm_book_magic_add(bvm_book_t* book);
bvm_errcode_t bvm_book_magic_remove(bvm_book_t* book);
bool bvm_book_magic_exists(bvm_book_t* book);

uint8_t bvm_book_get_chapters_max();
uint8_t bvm_book_get_chapters_total(const bvm_book_t* book);
uint8_t bvm_book_get_chapters_free(const bvm_book_t* book);

// slots start at 0
bool bvm_book_chapter_slot_is_free(const bvm_book_t* book, uint8_t slot);
int bvm_chapter_get_slot(const bvm_chapter_t* chapter);
size_t bvm_chapter_get_size(const bvm_chapter_t* chapter);
ssize_t bvm_chapter_slot_get_offset(uint8_t slot);
bvm_errcode_t bvm_book_get_random_free_slot(const bvm_book_t* book,
                                            uint8_t* slot);
bvm_errcode_t bvm_book_extent_free(bvm_book_t* book, size_t nextents,
                                   uint64_t* extent);
bvm_errcode_t bvm_book_extent_alloc_random(bvm_book_t* book, size_t nextents,
                                           uint64_t* extents);
bvm_errcode_t bvm_book_extent_mark_allocated(bvm_book_t* book, uint64_t extent);
/** chapter functions **/

/**
 * Encrypt chapter content based on chapter algorithm
 *
 * Encrypt in place by passing NULL and 0 to in and insize
 */
bvm_errcode_t bvm_chapter_encrypt(const bvm_chapter_t* chapter, uint8_t* out,
                                  size_t outsize, const uint8_t* in,
                                  size_t insize);
bvm_errcode_t bvm_chapter_decrypt(const bvm_chapter_t* chapter, uint8_t* out,
                                  size_t outsize, const uint8_t* in,
                                  size_t insize);

// used internally
bvm_errcode_t bvm_chapter_slot_encrypt(const bvm_chapter_t* chapter,
                                       uint8_t* out, size_t outsize,
                                       const uint8_t* in, size_t insize);
bvm_errcode_t bvm_chapter_slot_decrypt(const bvm_key_t* slot_key,
                                       const bvm_key_t* slot_iv, uint8_t* out,
                                       size_t outsize, const uint8_t* in,
                                       size_t insize);

/**
 * Add new chapter to book using key
 *
 * @param book book to add chapter to
 * @param[in] key key used for encryption
 * @param[in] total_extents number of extents to allocate for chapter
 **/
bvm_chapter_t* bvm_chapter_create_key(bvm_book_t* book, const bvm_key_t* key,
                                      size_t total_extents);
bvm_errcode_t bvm_chapter_write_slot(bvm_chapter_t* chapter);

/**
 * Open an already existing chapter using key
 *
 * @param book book to open chapter from
 * @param[in] key chapter encryption key
 **/
bvm_chapter_t* bvm_chapter_open_key(bvm_book_t* book, const bvm_key_t* key);

/**
 * Open an already existing chapter using key and specifying slot
 */
bvm_chapter_t* bvm_chapter_slot_open_key(bvm_book_t* book, uint8_t slot,
                                         const bvm_key_t* key);

void bvm_chapter_close(bvm_chapter_t* chapter);
bvm_errcode_t bvm_chapter_resize(bvm_chapter_t* chapter, size_t total_extents);

bvm_chapter_t* bvm_chapter_slot_open_key(bvm_book_t* book, uint8_t slot,
                                         const bvm_key_t* key);

#ifdef __cplusplus
}
#endif

#endif  // BVM_BVM_H

