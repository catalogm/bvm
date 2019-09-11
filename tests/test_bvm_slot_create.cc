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
using bvm::algorithms_type;
using bvm::Bootstrap;
using bvm::BVM;
using bvm::BVMPtr;
using bvm::iv_type;
using bvm::key_type;
using bvm::KeySlot;
using bvm::Layer;
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
  constexpr static size_t size = (1024 * 1024 * 1024) * 3ull / 2ull;  // 1.5gb
};

fs::path BVMSlotCreate::fname = "";

TEST_F(BVMSlotCreate, MaxSlots) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);
  ASSERT_EQ(vm->slots_used(), 0);

  std::string passphrase = "hello wurl";
  for (size_t i = 0; i < BVM::MAX_SLOTS; i++) {
    auto slot = vm->createSlot(passphrase);
    auto slotn = slot->slotn();
    ASSERT_LT(slotn, BVM::MAX_SLOTS);
    ASSERT_EQ(vm->slots_used(), i + 1);
  }
  ASSERT_EQ(vm->slots_used(), BVM::MAX_SLOTS);

  ASSERT_THROW({ vm->createSlot(passphrase); }, std::runtime_error);
  ASSERT_THROW({ vm->createSlot(""); }, std::runtime_error);
}

TEST_F(BVMSlotCreate, CreateAndWrite) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);
  ASSERT_EQ(vm->slots_used(), 0);

  ASSERT_EQ(sizeof(bvm::KeySlotPayload), 1048992);
  ASSERT_EQ(sizeof(bvm::KeySlotPayload) % 16, 0);

  // create slot
  std::string passphrase = "hello wurl";
  auto slot = vm->createSlot(passphrase);
  auto slotn = slot->slotn();
  ASSERT_LT(slotn, BVM::MAX_SLOTS);
  ASSERT_EQ(vm->slots_used(), 1);

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
  ASSERT_EQ(vm->slots_used(), 0);

  // test sizes
  ASSERT_EQ(vm->size(), size);
  ASSERT_EQ(vm->bootstrap_size(), sizeof(bvm::Bootstrap));
  ASSERT_EQ(vm->data_size(), size - sizeof(bvm::Bootstrap));
  ASSERT_EQ(vm->extents_total(), vm->data_size() / BVM::EXTENT_SIZE);
  ASSERT_EQ(vm->extents_free(), vm->extents_total());
  ASSERT_EQ(vm->extents_used(), 0);

  // create slot
  std::string passphrase = "hello wurl";
  auto slot = vm->createSlot(passphrase);
  auto slotn = slot->slotn();
  ASSERT_LT(slotn, BVM::MAX_SLOTS);
  ASSERT_EQ(vm->slots_used(), 1);

  // add volume
  Botan::AutoSeeded_RNG rng;
  vm->addVolume(slotn, 1,
                {{"aes-xts-plain64", rng.random_vec(512 / 8)},
                 {"twofish-xts-plain64", rng.random_vec(512 / 8)}});

  ASSERT_EQ(vm->extents_free(), vm->extents_total() - 1);
  ASSERT_EQ(vm->extents_used(), 1);
  ASSERT_EQ(slot->volumes().size(), 1);
  ASSERT_EQ(slot->volumes()[0].extent_size, BVM::EXTENT_SIZE);
  ASSERT_EQ(slot->volumes()[0].extents.size(), 1);
  ASSERT_EQ(slot->volumes()[0].layers.size(), 2);
  ASSERT_EQ(slot->volumes()[0].layers[0].cipher, "aes-xts-plain64");
  ASSERT_EQ(slot->volumes()[0].layers[0].key.size(), 512 / 8);
  ASSERT_EQ(slot->volumes()[0].layers[1].cipher, "twofish-xts-plain64");
  ASSERT_EQ(slot->volumes()[0].layers[1].key.size(), 512 / 8);

  // write slot
  ASSERT_TRUE(vm->writeSlot(slotn));

  // unlock should return nullptr if slot already open
  ASSERT_EQ(vm->unlockSlot(passphrase), nullptr);

  // close slot
  ASSERT_EQ(vm->slots_used(), 1);
  vm->closeSlot(slotn);
  ASSERT_EQ(vm->slots_used(), 0);
  ASSERT_EQ(vm->extents_free(), vm->extents_total());
  ASSERT_EQ(vm->extents_used(), 0);

  // unlock using key (derived from passphrase)
  {
    auto us = vm->unlockSlot(slot->key());
    ASSERT_NE(us, nullptr);
    ASSERT_EQ(slotn, us->slotn());
    ASSERT_EQ(vm->slots_used(), 1);
  }

  // close slot
  vm->closeSlot(slotn);
  ASSERT_EQ(vm->slots_used(), 0);
  ASSERT_EQ(vm->extents_used(), 0);

  // unlock slot
  auto us = vm->unlockSlot(passphrase);
  ASSERT_NE(us, nullptr);
  ASSERT_EQ(slotn, us->slotn());
  ASSERT_EQ(vm->slots_used(), 1);

  // check volumes
  ASSERT_EQ(vm->extents_free(), vm->extents_total() - 1);
  ASSERT_EQ(vm->extents_used(), 1);
  ASSERT_EQ(us->volumes().size(), 1);
  {
    auto &vol = us->volumes()[0];
    ASSERT_EQ(vol.extent_size, BVM::EXTENT_SIZE);
    ASSERT_EQ(vol.extents.size(), 1);
    ASSERT_EQ(vol.extents, slot->volumes()[0].extents);
    ASSERT_EQ(vol.layers[0].cipher, "aes-xts-plain64");
    ASSERT_EQ(vol.layers[0].key.size(), 512 / 8);
    ASSERT_EQ(vol.layers[1].cipher, "twofish-xts-plain64");
    ASSERT_EQ(vol.layers[1].key.size(), 512 / 8);
  }

  std::cout << fmt::format(
                   "concise "
                   "format:\n----------------------\n{}\n------------------",
                   vm->conciseDeviceMapper(slotn, 0, "bvm"))
            << std::endl;

  // remove volume
  vm->removeVolume(slotn, 0);
  ASSERT_EQ(vm->extents_free(), vm->extents_total());
  ASSERT_EQ(vm->extents_used(), 0);
  ASSERT_EQ(us->volumes().size(), 0);
}

