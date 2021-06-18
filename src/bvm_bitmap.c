/* Copyright 2021 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <limits.h> /* For CHAR_BIT */
#include <stdio.h>
#include <stdlib.h>

#include "bvm/bvm.h"

/* Source:
 * https://stackoverflow.com/questions/4372515/how-to-implement-a-bitset-in-c
 * http://c-faq.com/misc/bitsets.html
 **/
#define BITMASK(b) (1 << ((b) % CHAR_BIT))
#define BITSLOT(b) ((b) / CHAR_BIT)
#define BITSET(a, b) ((a)[BITSLOT(b)] |= BITMASK(b))
#define BITCLEAR(a, b) ((a)[BITSLOT(b)] &= ~BITMASK(b))
#define BITTEST(a, b) ((a)[BITSLOT(b)] & BITMASK(b))
#define BITNSLOTS(nb) ((nb + CHAR_BIT - 1) / CHAR_BIT)

/* TODO: bitmap can be allocated dynamically depending on max bit
 **/
bvm_bitmap_t* bvm_bitmap_create(size_t nbits) {
  size_t nchars = BITNSLOTS(nbits);
  char* bitarray = (char*)calloc(nchars, sizeof(char));
  if (bitarray == NULL) {
    fprintf(stderr,
            "bvm_bitmap_create: failed to allocate memory for bitarray\n");
    return NULL;
  }

  bvm_bitmap_t* bitmap = (bvm_bitmap_t*)calloc(1, sizeof(bvm_bitmap_t));
  if (bitmap == NULL) {
    fprintf(stderr,
            "bvm_bitmap_create: failed to allocate memory for bitmap\n");
    return NULL;
  }
  bitmap->bitarray = bitarray;
  bitmap->nbits = nbits;
  return bitmap;
}

void bvm_bitmap_free(bvm_bitmap_t* bitmap) {
  if (bitmap != NULL) {
    if (bitmap->bitarray != NULL) {
      free(bitmap->bitarray);
      bitmap->bitarray = NULL;
    }

    bitmap->nbits = 0;
    free(bitmap);
  }
}

size_t bvm_bitmap_size_bytes(const bvm_bitmap_t* bitmap) {
  return BITNSLOTS(bitmap->nbits);
}

void bvm_bitmap_printf(const bvm_bitmap_t* bitmap) {
  if (bitmap != NULL && bitmap->bitarray) {
    for (size_t i = 0; i < bitmap->nbits; i++) {
      bool val = BITTEST(bitmap->bitarray, i) > 0;
      putc(val ? '1' : '0', stdout);
      if (i != bitmap->nbits - 1) {
        putc(' ', stdout);
      }
    }
    putc('\n', stdout);
  } else {
    printf("NULL bitmap\n");
  }
}

void bvm_bitmap_bit_set(bvm_bitmap_t* bitmap, size_t bit) {
  if (bit >= bitmap->nbits) {
    fprintf(stderr, "bvm_bitmap_bit_set: bit %lu is out of range\n", bit);
    return;
  }
  BITSET(bitmap->bitarray, bit);
}

void bvm_bitmap_bit_clear(bvm_bitmap_t* bitmap, size_t bit) {
  if (bit >= bitmap->nbits) {
    fprintf(stderr, "bvm_bitmap_bit_clear: bit %lu is out of range\n", bit);
    return;
  }
  BITCLEAR(bitmap->bitarray, bit);
}

int bvm_bitmap_bit_test(const bvm_bitmap_t* bitmap, size_t bit) {
  if (bit >= bitmap->nbits) {
    fprintf(stderr, "bvm_bitmap_bit_test: bit %lu is out of range\n", bit);
    return -1;
  }
  return BITTEST(bitmap->bitarray, bit) > 0;
}

size_t bvm_bitmap_cardinality(const bvm_bitmap_t* bitmap) {
  size_t res = 0;
  for (size_t i = 0; i < bitmap->nbits; i++) {
    res += BITTEST(bitmap->bitarray, i) > 0;
  }
  return res;
}

