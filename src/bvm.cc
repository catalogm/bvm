/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include "bvm/bvm.hh"

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/pwdhash.h>
#include <algorithm>
#include <exception>
#include <iterator>

namespace fs = std::filesystem;
using namespace fmt::literals;
using json = nlohmann::json;
using bvm::Bootstrap;
using bvm::BVM;
using bvm::BVMPtr;
using bvm::KeySlot;
using bvm::KeySlotPayload;
using bvm::Slot;
using bvm::SlotPtr;

BVM::BVM(fs::path path) : path_{path}, fp_{}, size_{}, slots_{} {
  fp_.open(path, std::ios::binary | std::ios::in | std::ios::out);
  fp_.seekg(0, std::ios::end);
  size_ = fp_.tellg();
}

bool BVM::wipe(bool magic) { return wipeBootstrap(magic) && wipeData(); }

bool BVM::wipeBootstrap(bool magic) {
  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  auto bstrap = std::make_unique<Bootstrap>();
  Bootstrap& b = *bstrap;
  rng->randomize(reinterpret_cast<uint8_t*>(&b), sizeof(b));

  if (magic) {
    memset(b.magic, 0, sizeof(b.magic));
    strncpy(b.magic, MAGIC_HEADER.c_str(), sizeof(b.magic));
  }

  fp_.seekp(0);
  fp_.write(reinterpret_cast<char*>(&b), sizeof(b));
  fp_.flush();
  return true;
}

bool BVM::wipeData(uint64_t blocksize) {
  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  uint64_t s = size();
  std::vector<uint8_t> buf(blocksize, 0);

  fp_.seekp(sizeof(Bootstrap));
  uint64_t written = 0;
  while (written < s) {
    uint64_t left = s - written;
    uint64_t bs = left > blocksize ? blocksize : left;
    rng->randomize(buf.data(), bs);
    fp_.write(reinterpret_cast<char*>(buf.data()), bs);
    written += bs;
  }
  fp_.flush();
  return true;
}

SlotPtr BVM::createSlot(std::string passphrase) {
  if (slots_.size() >= MAX_SLOTS) {
    throw std::runtime_error("no more slots available in bootstrap");
  } else if (passphrase.empty()) {
    throw std::runtime_error("passphrase must not be empty");
  }

  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  auto argon = Botan::PasswordHashFamily::create("Argon2id");
  auto kdf = argon->default_params();

  auto salt = rng->random_vec(sizeof(KeySlot::salt));
  if (salt.size() != 32) {
    throw std::runtime_error("Invalid salt size: {}"_format(salt.size()));
  }
  auto key = Slot::key_type(64, 0);
  kdf->derive_key(key.data(), key.size(), passphrase.c_str(),
                  passphrase.length(), salt.data(), salt.size());
  return createSlot(salt, key);
}

SlotPtr BVM::createSlot(Botan::secure_vector<uint8_t> salt,
                        Botan::secure_vector<uint8_t> key) {
  if (slots_.size() >= MAX_SLOTS) {
    throw std::runtime_error("no more slots available in bootstrap");
  }

  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  uint8_t slotn = rng->next_byte() % (MAX_SLOTS - slots_.size());
  while (slots_.find(slotn) != slots_.end()) {
    slotn++;
  }

  auto slot = std::make_shared<Slot>(slotn, salt, key);
  slots_[slotn] = slot;
  return slot;
}

/*
SlotPtr BVM::unlockSlot(std::string passphrase) {
  if (slots_.size() >= MAX_SLOTS) {
    throw std::runtime_error("no more slots available in bootstrap");
  } else if (passphrase.empty()) {
    throw std::runtime_error("passphrase must not be empty");
  }

  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  auto argon = Botan::PasswordHashFamily::create("Argon2id");
  auto kdf = argon->default_params();

  auto salt = rng->random_vec(sizeof(KeySlot::salt));
  if (salt.size() != 32) {
    throw std::runtime_error("Invalid salt size: {}"_format(salt.size()));
  }
  auto key = Slot::key_type(64, 0);
  kdf->derive_key(key.data(), key.size(), passphrase.c_str(),
                  passphrase.length(), salt.data(), salt.size());
  return unlockSlot(key);
}
*/

bool BVM::writeSlot(uint8_t slotn) {
  if (slots_.find(slotn) == slots_.end()) {
    throw std::runtime_error("Invalid slot");
  }
  auto slot = slots_[slotn];
  auto bootstrap = std::make_unique<Bootstrap>();
  Bootstrap& b = *bootstrap;
  fp_.seekg(0);
  fp_.read(reinterpret_cast<char*>(&b), sizeof(b));

  slot->serialize(b.slots[slotn]);
  fp_.seekp(0);
  // TODO: only write the specific slot, not the entire bootstrap
  fp_.write(reinterpret_cast<char*>(&b), sizeof(b));
  fp_.flush();

  return true;
}

Slot::Slot(uint8_t slotn, salt_type salt, key_type key,
           std::vector<std::string> algorithms)
    : slotn_{slotn},
      salt_{std::move(salt)},
      iv_{},
      key_{std::move(key)},
      meta_{},
      algorithms_{std::move(algorithms)} {
  if (!algorithms_valid(algorithms_)) {
    throw std::runtime_error(
        "Invalid algorithms: {}"_format(fmt::join(algorithms_, ",")));
  }
}

void Slot::serialize(KeySlot& ks) {
  // randomize iv
  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  iv_ = rng->random_vec(sizeof(ks.iv));
  if (iv_.size() != sizeof(ks.iv)) {
    throw std::runtime_error(
        "Invalid iv size: {}, should be {}"_format(iv_.size(), sizeof(ks.iv)));
  }

  memcpy(ks.iv, iv_.data(), iv_.size());

  // allocate memory for plaintext payload
  auto payload = std::make_unique<KeySlotPayload>();
  KeySlotPayload& p = *payload;
  memset(&p, 0, sizeof(p));

  // serialize meta to cbor
  std::vector<uint8_t> v_cbor = json::to_cbor(meta_);
  if (v_cbor.size() > sizeof(p.data.meta)) {
    throw std::runtime_error(
        "Metadata is too large ({}), needs to be smaller than: {}"_format(
            v_cbor.size(), sizeof(p.data.meta)));
  }

  // copy meta to payload
  memcpy(p.data.meta, v_cbor.data(), v_cbor.size());

  // checksum
  {
    auto sha256 = Botan::HashFunction::create_or_throw("SHA-256");
    auto hash =
        sha256->process(reinterpret_cast<uint8_t*>(&p.data), sizeof(p.data));
    if (hash.size() != sizeof(p.sha256_checksum)) {
      throw std::runtime_error(fmt::format(
          "payload sha256 checksum size ({}) is not equal to hash size ({})",
          sizeof(p.sha256_checksum), hash.size()));
    }
    memcpy(p.sha256_checksum, hash.data(), hash.size());
  }

  // encrypt payload
  auto enc = Botan::Cipher_Mode::create(algorithms_.front(), Botan::ENCRYPTION);
  Botan::secure_vector<uint8_t> ctext(
      reinterpret_cast<uint8_t*>(&p),
      reinterpret_cast<uint8_t*>(&p) + sizeof(p));
  for (auto& alg : algorithms_) {
    encrypt(alg, key_, iv_, ctext);
  }

  // copy payload to slot
  if (sizeof(ks.payload) != ctext.size()) {
    throw std::runtime_error(
        "keyslot payload size ({}) is not equal to ciphertext size ({})"_format(
            sizeof(ks.payload), ctext.size()));
  }
  memcpy(&ks.payload, ctext.data(), ctext.size());
}

bool Slot::algorithms_valid(const std::vector<std::string>& algorithms) {
  if (algorithms.size() < 1 || algorithms.size() > 3) {
    return false;
  }

  for (auto& alg : algorithms) {
    bool found = std::find(VALID_ALGORITHMS.begin(), VALID_ALGORITHMS.end(),
                           alg) != VALID_ALGORITHMS.end();
    if (!found) {
      return false;
    }
  }
  return true;
}

void Slot::encrypt(const std::string& algorithm,
                   const Botan::secure_vector<uint8_t>& key,
                   const Botan::secure_vector<uint8_t>& iv,
                   Botan::secure_vector<uint8_t>& ctext) {
  auto enc = Botan::Cipher_Mode::create(algorithm, Botan::ENCRYPTION);
  if (iv.size() < enc->default_nonce_length()) {
    throw std::runtime_error(
        "Invalid iv size: {}"_format(enc->default_nonce_length()));
  }
  enc->set_key(key);
  enc->start(iv);
  enc->finish(ctext);
}

void Slot::decrypt(const std::string& algorithm,
                   const Botan::secure_vector<uint8_t>& key,
                   const Botan::secure_vector<uint8_t>& iv,
                   Botan::secure_vector<uint8_t>& ctext) {
  auto enc = Botan::Cipher_Mode::create(algorithm, Botan::DECRYPTION);
  if (iv.size() < enc->default_nonce_length()) {
    throw std::runtime_error(
        "Invalid iv size: {}"_format(enc->default_nonce_length()));
  }
  enc->set_key(key);
  enc->start(iv);
  enc->finish(ctext);
}
