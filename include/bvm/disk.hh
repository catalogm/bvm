/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */
#ifndef INCLUDE_BVM_DISK_HH_
#define INCLUDE_BVM_DISK_HH_

#include <cstdint>

namespace bvm {

#define BVM_DISK_FORMAT_VERSION 0
#define BVM_DISK_MAX_SLOTS 16

#pragma pack(push, 1)
struct KeySlotPayload {
  uint8_t sha256_checksum[32];
  struct {
    uint32_t meta_size;
    uint8_t meta[1024 * 1024];  // cbor data
    uint8_t _reserved1[16];
    uint8_t _reserved2[124];
  } data;
  /*
  {
    "version": 0,
    "volumes": [{
      "key": "", // 64 bytes
      "algorithms": ["aes-xts-plain64"],
      "extent_size": 1024 * 1024 * 1024
      "extents": [1, 2, 3],
    }],
  }
  */
};

struct KeySlot {
  uint8_t salt[32];  // used for argon2id
  uint8_t iv[32];    // used for key iv
  // encrypted with chosen algorithm
  KeySlotPayload payload;
};

struct Bootstrap {
  char magic[5];
  KeySlot slots[BVM_DISK_MAX_SLOTS];
  uint8_t _reserved[251];
};
#pragma pack(pop)

// POD operators
bool operator<(const KeySlot& lhs, const KeySlot& rhs);
bool operator==(const KeySlot& lhs, const KeySlot& rhs);
};  // namespace bvm

#endif  // INCLUDE_BVM_DISK_HH_
