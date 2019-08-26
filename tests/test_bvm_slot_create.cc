/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <gtest/gtest.h>

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include <cmath>
#include <cstdio>

#include "bvm/bvm.hh"

namespace fs = std::filesystem;
using bvm::Bootstrap;
using bvm::BVM;
using bvm::BVMPtr;
using bvm::iv_type;
using bvm::key_type;
using bvm::KeySlot;
using bvm::salt_type;
using bvm::Slot;

class BVMSlotCreate : public ::testing::Test {
 protected:
  static void SetUpTestCase() {}

  static void TearDownTestCase() {}

  void SetUp() override {
    constexpr size_t blocksize = 4096;
    fname = std::tmpnam(nullptr);

    {
      std::fstream fp(fname, std::ios::binary | std::ios::out);
      std::vector<uint8_t> buf(blocksize, 0);
      size_t written = 0;
      while (written < size) {
        size_t left = std::min(buf.size(), size - written);
        fp.write(reinterpret_cast<char *>(buf.data()), left);
        written += left;
      }
    }
  }

  void TearDown() override { fs::remove(fname); }

  static fs::path fname;
  constexpr static size_t size = (1024 * 1024 * 1024) * 3ull / 2ull;
};

fs::path BVMSlotCreate::fname = "";

TEST_F(BVMSlotCreate, MaxSlots) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);
  ASSERT_EQ(vm->slots_size(), 0);

  std::string passphrase = "hello wurl";
  for (size_t i = 0; i < BVM::MAX_SLOTS; i++) {
    auto slot = vm->createSlot(passphrase);
    auto slotn = slot->slotn();
    ASSERT_LT(slotn, BVM::MAX_SLOTS);
    ASSERT_EQ(vm->slots_size(), i + 1);
  }
  ASSERT_EQ(vm->slots_size(), BVM::MAX_SLOTS);

  ASSERT_THROW({ vm->createSlot(passphrase); }, std::runtime_error);
  ASSERT_THROW({ vm->createSlot(""); }, std::runtime_error);
}

TEST_F(BVMSlotCreate, CreateAndWrite) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);
  ASSERT_EQ(vm->slots_size(), 0);

  ASSERT_EQ(sizeof(bvm::KeySlotPayload), 1048752);
  ASSERT_EQ(sizeof(bvm::KeySlotPayload) % 16, 0);

  // create slot
  std::string passphrase = "hello wurl";
  auto slot = vm->createSlot(passphrase);
  auto slotn = slot->slotn();
  ASSERT_LT(slotn, BVM::MAX_SLOTS);
  ASSERT_EQ(vm->slots_size(), 1);

  // write slot
  ASSERT_TRUE(vm->writeSlot(slotn));

  // read bootstrap
  auto bootstrap = std::make_unique<Bootstrap>();
  Bootstrap &b = *bootstrap;
  {
    std::fstream fp(fname, std::ios::binary | std::ios::in);
    fp.read(reinterpret_cast<char *>(&b), sizeof b);
  }

  // not expected to be zeros
  auto expected_bootstrap = std::make_unique<Bootstrap>();
  Bootstrap &exp = *expected_bootstrap;
  memset(&exp, 0, sizeof exp);
  ASSERT_NE(memcmp(&b, &exp, sizeof exp), 0);

  // compare rest of bootstrap which should be zero except the slot
  memcpy(&exp.slots[slotn], &b.slots[slotn], sizeof(KeySlot));
  ASSERT_EQ(memcmp(&b, &exp, sizeof exp), 0);
}

TEST_F(BVMSlotCreate, UnlockSlot) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);
  ASSERT_EQ(vm->slots_size(), 0);

  // create slot
  std::string passphrase = "hello wurl";
  auto slot = vm->createSlot(passphrase);
  auto slotn = slot->slotn();
  ASSERT_LT(slotn, BVM::MAX_SLOTS);
  ASSERT_EQ(vm->slots_size(), 1);

  // write slot
  ASSERT_TRUE(vm->writeSlot(slotn));

  // unlock should return nullptr if slot already open
  ASSERT_EQ(vm->unlockSlot(passphrase), nullptr);

  // close slot
  ASSERT_EQ(vm->slots_size(), 1);
  vm->closeSlot(slotn);
  ASSERT_EQ(vm->slots_size(), 0);

  // unlock slot
  auto us = vm->unlockSlot(passphrase);
  ASSERT_NE(us, nullptr);
  ASSERT_EQ(slotn, us->slotn());
  ASSERT_EQ(vm->slots_size(), 1);
}

