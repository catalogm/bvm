/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <gtest/gtest.h>

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <exception>

#include "bvm/bvm.hh"

using bvm::iv_type;
using bvm::key_type;
using bvm::KeySlot;
using bvm::salt_type;
using bvm::Slot;

TEST(BVMSlot, EncryptDecrypt) {
  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  auto iv = rng->random_vec(sizeof(KeySlot::iv));
  auto siv = Botan::secure_vector<uint8_t>(iv.begin(), iv.begin() + 16);
  auto key = key_type(64, 2);
  auto ctext = Botan::secure_vector<uint8_t>(16 * 10, 3);
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

  Slot::decrypt(alg, key, siv, ctext);
  ASSERT_EQ(ctext, orig);
  ASSERT_EQ(ctext, expected);

  // IV invalid size
  {
    auto enc = Botan::Cipher_Mode::create(alg, Botan::ENCRYPTION);
    iv.resize(enc->default_nonce_length() - 1);
    ASSERT_THROW({ Slot::encrypt(alg, key, iv, ctext); }, std::runtime_error);
  }
}

TEST(BVMSlot, SerializeAndDeserialize) {
  auto salt = salt_type(32, 1);
  auto key = key_type(64, 2);
  auto wrong_key = key_type(64, 10);

  auto orig = std::make_unique<KeySlot>();
  memset(orig.get(), 0, sizeof(*orig));

  auto sks = std::make_unique<KeySlot>(*orig);
  ASSERT_NE(orig, sks);    // pointer compare
  ASSERT_EQ(*orig, *sks);  // data compare
  ASSERT_EQ(memcmp(orig.get(), sks.get(), sizeof *sks),
            0);  // just to make sure

  Slot slot(3, salt, key);
  slot.serialize(*sks);

  auto meta = slot.meta();
  ASSERT_EQ(meta.version, BVM_DISK_FORMAT_VERSION);
  ASSERT_EQ(meta.volumes.size(), 0);

  ASSERT_EQ(sizeof sks->salt, salt.size());
  ASSERT_EQ(memcmp(sks->salt, salt.data(), salt.size()), 0);

  auto dks = std::make_unique<KeySlot>(*sks);
  ASSERT_NE(dks, sks);    // pointer compare
  ASSERT_EQ(*dks, *sks);  // data compare

  // using wrong key should fail
  ASSERT_EQ(Slot::deserialize(5, wrong_key, *dks), nullptr);

  auto ds = Slot::deserialize(5, key, *dks);
  ASSERT_NE(ds, nullptr);

  auto dsm = ds->meta();
  ASSERT_EQ(dsm.version, 0);
  ASSERT_EQ(dsm.volumes.size(), 0);
}

TEST(BVMSlot, ObjectAllocate) {
  auto iv = iv_type();
  auto key = key_type(32, 2);
  auto salt = salt_type(32, 1);
  Slot(3, salt, key);
  Slot(3, salt, key, {"AES-256/XTS"});
  Slot(3, salt, key, {"Twofish/XTS", "AES-256/XTS"});
  Slot(3, salt, key, {"Twofish/XTS", "AES-256/XTS", "Serpent/XTS"});

  {
    auto slot = Slot(3, salt, key);
    ASSERT_EQ(slot.slotn(), 3);
    ASSERT_EQ(slot.iv(), iv_type());
    ASSERT_EQ(slot.key(), key);
    ASSERT_EQ(slot.salt(), salt);

    auto& meta = slot.meta();
    ASSERT_EQ(meta.version, BVM_DISK_FORMAT_VERSION);
    ASSERT_EQ(meta.volumes.size(), 0);
  }

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

