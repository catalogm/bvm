/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */
#include "bvm/disk.hh"

#include <cstring>
#include <type_traits>

#include "hedley/hedley.h"

using bvm::Bootstrap;
using bvm::KeySlotPayload;

// static disk format asserts
HEDLEY_STATIC_ASSERT(std::is_pod<Bootstrap>::value,
                     "bvm::Bootstrap must be a POD data type");
/*
HEDLEY_STATIC_ASSERT(sizeof(Bootstrap) % 4096 == 0,
                     "sizeof bvm::Bootstrap must be divisible by 4096");
HEDLEY_STATIC_ASSERT(sizeof(KeySlotPayload) % 16 == 0,
                     "sizeof bvm::KeySlotPayload must be divisible by 16");
*/

bool bvm::operator<(const KeySlot& lhs, const KeySlot& rhs) {
  return memcmp(&lhs, &rhs, sizeof lhs) < 0;
}

bool bvm::operator==(const KeySlot& lhs, const KeySlot& rhs) {
  return memcmp(&lhs, &rhs, sizeof lhs) == 0;
}

