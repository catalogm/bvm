/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <gtest/gtest.h>

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

class BVMWipe : public ::testing::Test {
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

fs::path BVMWipe::fname = "";

TEST_F(BVMWipe, TestWipeOnlyBootstrap) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);
  ASSERT_TRUE(vm != nullptr);

  ASSERT_EQ(vm->path(), fname);
  ASSERT_EQ(vm->size(), size);

  // wipe bootstrap, magic should be false by default.
  ASSERT_TRUE(vm->wipeBootstrap());

  // read bootstrap
  auto bootstrap = std::make_unique<Bootstrap>();
  Bootstrap &b = *bootstrap;
  {
    std::fstream fp(fname, std::ios::binary | std::ios::in);
    fp.read(reinterpret_cast<char *>(&b), sizeof b);
  }

  // not expected to be zeros
  auto not_expected_bootstrap = std::make_unique<Bootstrap>();
  Bootstrap &nexp = *not_expected_bootstrap;
  memset(&nexp, 0, sizeof nexp);
  ASSERT_NE(memcmp(&b, &nexp, sizeof nexp), 0);

  // wipe with magic
  ASSERT_TRUE(vm->wipeBootstrap(true));

  // magic should be set
  {
    std::fstream fp(fname, std::ios::binary | std::ios::in);
    fp.read(reinterpret_cast<char *>(&b), sizeof b);
  }

  std::vector<uint8_t> magic{'B', 'V', 'M', 0, 0};
  ASSERT_EQ(sizeof(b.magic), magic.size());
  ASSERT_EQ(memcmp(b.magic, magic.data(), magic.size()), 0);
}

TEST_F(BVMWipe, TestWipeOnlyVolume) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);

  // wipe only data
  ASSERT_TRUE(vm->wipeData());

  // read bootstrap
  auto bootstrap = std::make_unique<Bootstrap>();
  Bootstrap &b = *bootstrap;
  {
    std::fstream fp(fname, std::ios::binary | std::ios::in);
    fp.read(reinterpret_cast<char *>(&b), sizeof b);
  }

  // expected to be zeros
  auto expected_bootstrap = std::make_unique<Bootstrap>();
  Bootstrap &exp = *expected_bootstrap;
  memset(&exp, 0, sizeof exp);
  ASSERT_EQ(memcmp(&b, &exp, sizeof exp), 0);

  // chance of this test failing is low, check data wiped
  {
    bool wiped = false;
    std::fstream fp(fname, std::ios::binary | std::ios::in);
    fp.seekg(sizeof(Bootstrap));
    for (int i = 0; i < 100; i++) {
      char c = 0;
      fp.get(c);
      if (c != 0) {
        wiped = true;
        break;
      }
    }
    ASSERT_TRUE(wiped);
  }
}

TEST_F(BVMWipe, TestWipeAll) {
  BVMPtr vm = std::make_shared<BVM>(fname);
  ASSERT_NE(vm, nullptr);
  ASSERT_TRUE(vm != nullptr);

  // wipe bootstrap, magic should be false by default.
  ASSERT_TRUE(vm->wipe());

  // read bootstrap
  auto bootstrap = std::make_unique<Bootstrap>();
  Bootstrap &b = *bootstrap;
  {
    std::fstream fp(fname, std::ios::binary | std::ios::in);
    fp.read(reinterpret_cast<char *>(&b), sizeof b);
  }

  // not expected to be zeros
  auto not_expected_bootstrap = std::make_unique<Bootstrap>();
  Bootstrap &nexp = *not_expected_bootstrap;
  memset(&nexp, 0, sizeof nexp);
  ASSERT_NE(memcmp(&b, &nexp, sizeof nexp), 0);

  // chance of the test failing is low, check data wiped
  {
    bool wiped = false;
    std::fstream fp(fname, std::ios::binary | std::ios::in);
    fp.seekg(sizeof(Bootstrap));
    for (int i = 0; i < 100; i++) {
      char c = 0;
      fp.get(c);
      if (c != 0) {
        wiped = true;
        break;
      }
    }
    ASSERT_TRUE(wiped);
  }
}

