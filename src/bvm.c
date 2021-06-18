/* Copyright 2021 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include "bvm/bvm.h"

#include <gcrypt.h>
#include <stdio.h>

#include "log.h"

const char* bvm_strerror(bvm_errcode_t err) {
  switch (err) {
    case BVM_OK:
      return NULL;
    case BVM_ERROR:
      return "Generic error";
    case BVM_ERROR_DEVICE_CLOSED:
      return "Device is already closed";
    case BVM_ERROR_DEVICE_IO:
      return "Device IO error";
    case BVM_ERROR_NO_CHAPTERS_FREE:
      return "No chapter slots free";
    case BVM_ERROR_NO_EXTENT_SPACE:
      return "No space left for extents";
    case BVM_ERROR_CHAPTER_SERIALIZE:
      return "Failed to serialize chapter";
    case BVM_ERROR_CHAPTER_DESERIALIZE:
      return "Failed to deserialize chapter";
    case BVM_ERROR_CHAPTER_ENCRYPT:
      return "Failed to encrypted chapter data";
    default:
      return NULL;
  }
  return NULL;
}

bool bvm_gcrypt_init() {
  /* Version check should be the very first call because it
   *      makes sure that important subsystems are initialized.
   *           #define NEED_LIBGCRYPT_VERSION to the minimum required version.
   */
  if (!gcry_check_version(BVM_NEED_LIBGCRYPT_VERSION)) {
    log_error("libgcrypt is too old (need %s, have %s)",
              BVM_NEED_LIBGCRYPT_VERSION, gcry_check_version(NULL));
    return false;
  }

  /* We don't want to see any warnings, e.g. because we have not yet
   *      parsed program options which might be used to suppress such
   *           warnings. */
  //  gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);

  /* Allocate a pool of 16k secure memory.  This makes the secure memory
   *      available and also drops privileges where needed.  Note that by
   *           using functions like gcry_xmalloc_secure and gcry_mpi_snew
   * Libgcrypt may expand the secure memory pool with memory which lacks the
   *                     property of not being swapped out to disk.   */
  gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);

  /* It is now okay to let Libgcrypt complain when there was/is
   *      a problem with the secure memory. */
  gcry_control(GCRYCTL_RESUME_SECMEM_WARN);

  return true;
}

bool bvm_init() {
  if (!bvm_gcrypt_init()) {
    return false;
  }

  /* Tell Libgcrypt that initialization has completed. */
  gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);

  // setup cbor malloc to use gcry secure
  // TODO: cbor_set_allocs(gcry_malloc, gcry_realloc, gcry_free);

  return true;
}

bvm_book_t* bvm_book_open_dev(bvm_dev_t* dev) {
  if (dev == NULL) {
    return NULL;
  }

  if (bvm_dev_get_size(dev) < BVM_DEV_MIN_SIZE) {
    log_error("bvm_book_open_dev: size must be greater than %lu",
              BVM_DEV_MIN_SIZE);
    bvm_dev_close(dev);
    return NULL;
  }

  bvm_book_t* book = (bvm_book_t*)calloc(1, sizeof(bvm_book_t));
  book->extent_size = BVM_EXTENT_SIZE;
  book->dev = dev;

  // allocate bitmap
  size_t total = bvm_book_get_extents_total(book);
  if (book->bitmap == NULL) {
    book->bitmap = bvm_bitmap_create(total);
    bvm_bitmap_bit_set(book->bitmap, 0);
  }

  return book;
}

bvm_book_t* bvm_book_memopen(void* mem, size_t size) {
  bvm_dev_t* dev = bvm_dev_memopen(mem, size);
  return bvm_book_open_dev(dev);
}

void bvm_book_close(bvm_book_t* book) {
  for (size_t i = 0; i < bvm_book_get_chapters_max(); i++) {
    bvm_chapter_t* ch = book->chapters[i];
    if (ch != NULL) {
      bvm_chapter_close(ch);
      book->chapters[i] = NULL;
    }
  }

  if (book->dev != NULL) {
    bvm_dev_close(book->dev);
  }

  if (book->bitmap != NULL) {
    bvm_bitmap_free(book->bitmap);
  }

  free(book);
}

bvm_dev_t* bvm_dev_create(bvm_dev_ops_t ops, void* user) {
  bvm_dev_t* dev = (bvm_dev_t*)calloc(1, sizeof(bvm_dev_t));
  if (dev == NULL) {
    log_error("bvm_dev_create: failed to allocate memory for dev");
    return NULL;
  }

  dev->ops = ops;
  dev->user = user;
  return dev;
}

const char* bvm_dev_get_name(bvm_dev_t* dev) { return dev->ops.name; }

size_t bvm_dev_get_size(bvm_dev_t* dev) { return dev->ops.get_size(dev); }

ssize_t bvm_dev_get_blocksize(bvm_dev_t* dev) {
  return dev->ops.get_blocksize(dev);
}

bvm_errcode_t bvm_dev_close(bvm_dev_t* dev) {
  if (dev == NULL) {
    log_error("bvm_dev_close: device is null");
    return BVM_ERROR_DEVICE_CLOSED;
  }

  bvm_errcode_t err = dev->ops.close(dev);
  free(dev);
  return err;
}

ssize_t bvm_dev_read(bvm_dev_t* dev, void* buf, size_t nbyte, size_t offset) {
  return dev->ops.read(dev, buf, nbyte, offset);
}

ssize_t bvm_dev_write(bvm_dev_t* dev, const void* buf, size_t nbyte,
                      size_t offset) {
  return dev->ops.write(dev, buf, nbyte, offset);
}

bvm_errcode_t bvm_dev_flush(bvm_dev_t* dev) { return dev->ops.flush(dev); }

bvm_dev_t* bvm_book_get_dev(bvm_book_t* book) {
  if (book == NULL) {
    return NULL;
  }
  return book->dev;
}

size_t bvm_book_get_size(bvm_book_t* book) {
  return bvm_dev_get_size(book->dev);
}

size_t bvm_book_get_extent_size(const bvm_book_t* book) {
  return book->extent_size;
}

size_t bvm_book_get_extents_total(bvm_book_t* book) {
  ssize_t es = bvm_book_get_extent_size(book);
  ssize_t size = bvm_book_get_size(book);
  if (es < 1 || size < 1) {
    log_error(
        "bvm_book_get_extents_total: book size and extent size must be greater "
        "than 1");
    return 0;
  }

  if (size < es) {
    log_error(
        "bvm_book_getextents_total: size must be greather 2 * extent_size");
    return 0;
  }

  return size / es;
}

size_t bvm_book_get_extents_used(const bvm_book_t* book) {
  if (book->bitmap == NULL) {
    return BVM_HEADER_EXTENTS_REQUIRED;
  }
  return bvm_bitmap_cardinality(book->bitmap);
}

size_t bvm_book_get_extents_free(bvm_book_t* book) {
  size_t total = bvm_book_get_extents_total(book);

  if (book->bitmap != NULL) {
    size_t used = bvm_book_get_extents_used(book);
    if (used >= total) {
      return 0;
    }
    return total - used;
  }

  if (total > BVM_HEADER_EXTENTS_REQUIRED) {
    return total - BVM_HEADER_EXTENTS_REQUIRED;
  }
  return 0;
}

bvm_errcode_t bvm_book_magic_add(bvm_book_t* book) {
  char magic[BVM_MAGIC_HEADER_SIZE];
  memcpy(magic, BVM_MAGIC_HEADER, sizeof(magic));
  bvm_dev_t* dev = bvm_book_get_dev(book);
  ssize_t res = bvm_dev_write(dev, magic, sizeof(magic), 0);
  if (res != sizeof(magic)) {
    return BVM_ERROR_DEVICE_IO;
  }
  return BVM_OK;
}

bvm_errcode_t bvm_book_magic_remove(bvm_book_t* book) {
  char magic[BVM_MAGIC_HEADER_SIZE];
  memset(magic, 0, sizeof(magic));
  bvm_dev_t* dev = bvm_book_get_dev(book);
  ssize_t res = bvm_dev_write(dev, magic, sizeof(magic), 0);
  if (res != sizeof(magic)) {
    return BVM_ERROR_DEVICE_IO;
  }
  return BVM_OK;
}

bool bvm_book_magic_exists(bvm_book_t* book) {
  char magic[BVM_MAGIC_HEADER_SIZE];
  bvm_dev_t* dev = bvm_book_get_dev(book);
  ssize_t res = bvm_dev_read(dev, magic, sizeof(magic), 0);
  return res == sizeof(magic) &&
         memcmp(magic, BVM_MAGIC_HEADER, sizeof(magic)) == 0;
}

uint8_t bvm_book_get_chapters_max() { return BVM_BOOK_CHAPTERS_MAX; }

uint8_t bvm_book_get_chapters_total(const bvm_book_t* book) {
  if (book == NULL) {
    return 0;
  }

  size_t chs = 0;
  for (uint8_t i = 0; i < bvm_book_get_chapters_max(); i++) {
    if (book->chapters[i] != NULL) {
      chs++;
    }
  }
  return chs;
}

uint8_t bvm_book_get_chapters_free(const bvm_book_t* book) {
  uint8_t max_ch = bvm_book_get_chapters_max();
  uint8_t total = bvm_book_get_chapters_total(book);
  return total > max_ch ? 0 : max_ch - total;
}

bool bvm_book_chapter_slot_is_free(const bvm_book_t* book, uint8_t slot) {
  if (slot >= bvm_book_get_chapters_max()) {
    return false;
  }

  return book->chapters[slot] == NULL;
}

bvm_errcode_t bvm_book_get_random_free_slot(const bvm_book_t* book,
                                            uint8_t* slot) {
  uint8_t free_chapters = bvm_book_get_chapters_free(book);
  if (free_chapters < 1) {
    log_error("No free chapters");
    return BVM_ERROR_NO_CHAPTERS_FREE;
  }

  uint8_t rnd = 0;  // random offset of slot within free slots
  gcry_randomize(&rnd, sizeof(rnd), GCRY_VERY_STRONG_RANDOM);
  rnd = rnd % free_chapters;

  uint8_t seen = 0;
  for (uint8_t i = 0; i < bvm_book_get_chapters_max(); i++) {
    if (!bvm_book_chapter_slot_is_free(book, i)) {
      continue;
    }

    if (seen >= rnd) {
      *slot = i;
      return BVM_OK;
    }

    seen++;
  }

  return BVM_ERROR;  // should not reach here
}

bvm_errcode_t bvm_book_extent_mark_allocated(bvm_book_t* book,
                                             uint64_t extent) {
  bvm_bitmap_t* bitmap = book->bitmap;
  if (bitmap == NULL) {
    log_error("bvm_book_extent_mark_allocated: bitmap is null");
    return BVM_ERROR;
  }

  if (bvm_bitmap_bit_test(bitmap, extent) != 0) {
    return BVM_ERROR;
  }

  bvm_bitmap_bit_set(bitmap, extent);
  return BVM_OK;
}

bvm_errcode_t bvm_book_extent_alloc_random(bvm_book_t* book, size_t nextents,
                                           uint64_t* extents) {
  /**
   * Notes:
   * - Can't allocate extents and shuffle array because only allocated at start
   * and it should be random within device
   */
  size_t free_extents = bvm_book_get_extents_free(book);
  if (free_extents < nextents) {
    log_error(
        "bvm_book_alloc_extents_random: not enough space for extent "
        "allocation");
    return BVM_ERROR_NO_EXTENT_SPACE;
  }

  if (nextents == 0) {
    return BVM_OK;
  }

  bvm_bitmap_t* bitmap = book->bitmap;
  if (bitmap == NULL) {
    log_error("bvm_book_alloc_extents_random: bitmap is null");
    return BVM_ERROR;
  }

  size_t total = bvm_book_get_extents_total(book);
  for (size_t a = 0; a < nextents; a++) {
    uint64_t rnd = 0;  // random offset of extent within free extents
    gcry_randomize(&rnd, sizeof(rnd), GCRY_VERY_STRONG_RANDOM);
    rnd = rnd % free_extents;

    size_t seen = 0;
    for (size_t i = 0; i < total; i++) {
      if (bvm_bitmap_bit_test(bitmap, i) != 0) {
        continue;
      }

      if (seen >= rnd) {
        bvm_bitmap_bit_set(bitmap, i);
        free_extents--;  // we used one
        if (extents != NULL) {
          extents[a] = i;
        }
        break;
      }

      seen++;
    }
  }

  return BVM_OK;
}

bvm_errcode_t bvm_book_extent_free(bvm_book_t* book, size_t nextents,
                                   uint64_t* extents) {
  if (book != NULL && book->bitmap != NULL && extents != NULL) {
    for (size_t i = 0; i < nextents; i++) {
      if (extents[i] > 0) {  // first extent is always allocated
        bvm_bitmap_bit_clear(book->bitmap, extents[i]);
      }
    }
  }
  return BVM_OK;
}

ssize_t bvm_chapter_slot_get_offset(uint8_t slot) {
  if (slot >= bvm_book_get_chapters_max()) {
    return -1;
  }
  return BVM_HEADER_SIZE + (slot * BVM_CHAPTER_SLOT_SIZE);
}

