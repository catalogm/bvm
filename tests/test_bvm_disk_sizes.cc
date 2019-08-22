/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <gtest/gtest.h>

#include "bvm/bvm.hh"

using bvm::Bootstrap;
using bvm::KeySlotPayload;

TEST(BVMDiskSizes, BootstrapAlignment) {
  // 4K disk block size
  ASSERT_EQ(sizeof(Bootstrap) % 4096, 0);
}

TEST(BVMDiskSizes, KeyPayloadAlignment) {
  // key payload is divisible by 128bits (16 bytes)
  ASSERT_EQ(sizeof(KeySlotPayload) % 16, 0);
}
