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
using bvm::KeySlot;
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

TEST_F(BVMSlotCreate, SlotObjectAllocate) {
  auto iv = Slot::iv_type();
  auto key = Slot::key_type(32, 2);
  auto salt = Slot::salt_type(32, 1);
  Slot(3, salt, key);
  Slot(3, salt, key, {"AES-256/XTS"});
  Slot(3, salt, key, {"Twofish/XTS", "AES-256/XTS"});
  Slot(3, salt, key, {"Twofish/XTS", "AES-256/XTS", "Serpent/XTS"});

  ASSERT_THROW({ Slot(3, salt, key, {"Invalid"}); }, std::runtime_error);
  ASSERT_THROW(
      {
        Slot(3, salt, key, {"AES-256/XTS", "Invalid"});
      },
      std::runtime_error);

  // size greater than 0
  ASSERT_THROW({ Slot(3, salt, key, {}); }, std::runtime_error);
  // size less than 3
  ASSERT_THROW(
      {
        Slot(3, salt, key,
             {"AES-256/XTS", "Twofish/XTS", "Serpent/XTS", "AES-256/XTS"});
      },
      std::runtime_error);
}

TEST_F(BVMSlotCreate, EncryptDecrypt) {
  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  auto iv = rng->random_vec(sizeof(KeySlot::iv));
  auto siv = Botan::secure_vector<uint8_t>(iv.begin(), iv.begin() + 16);
  auto key = Slot::key_type(64, 2);
  auto ctext = Botan::secure_vector<uint8_t>(16 * 10, 0);
  auto orig = ctext;
  std::string alg = "AES-256/XTS";

  auto expected = orig;
  // encrypt expected
  {
    auto enc = Botan::Cipher_Mode::create(alg, Botan::ENCRYPTION);
    enc->set_key(key);
    enc->start(siv);
    enc->finish(expected);
    ASSERT_NE(expected, orig);
  }

  {
    Slot::encrypt(alg, key, siv, ctext);
    ASSERT_NE(ctext, orig);
    ASSERT_EQ(ctext, expected);
  }

  // decrypt expected
  {
    auto enc = Botan::Cipher_Mode::create(alg, Botan::DECRYPTION);
    enc->set_key(key);
    enc->start(siv);
    enc->finish(expected);
    ASSERT_EQ(expected, orig);
    ASSERT_NE(expected, ctext);
  }

  {
    Slot::decrypt(alg, key, siv, ctext);
    ASSERT_EQ(ctext, orig);
    ASSERT_EQ(ctext, expected);
  }
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

TEST_F(BVMSlotCreate, SetAlgorithm) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);
  ASSERT_EQ(vm->slots_size(), 0);
}
