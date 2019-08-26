/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include "bvm/bvm.hh"

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/pwdhash.h>
#include <algorithm>
#include <exception>
#include <iterator>
#include <type_traits>

#include "hedley/hedley.h"

namespace fs = std::filesystem;
using namespace fmt::literals;
using json = nlohmann::json;
using bvm::Bootstrap;
using bvm::BVM;
using bvm::BVMPtr;
using bvm::key_type;
using bvm::KeySlot;
using bvm::KeySlotPayload;
using bvm::Slot;
using bvm::SlotMeta;
using bvm::SlotPtr;
using bvm::VolumeMeta;

// static disk format asserts
HEDLEY_STATIC_ASSERT(std::is_pod<Bootstrap>::value,
                     "bvm::Bootstrap must be a POD data type");

bool bvm::operator<(const KeySlot& lhs, const KeySlot& rhs) {
  return memcmp(&lhs, &rhs, sizeof lhs) < 0;
}

bool bvm::operator==(const KeySlot& lhs, const KeySlot& rhs) {
  return memcmp(&lhs, &rhs, sizeof lhs) == 0;
}

void bvm::to_json(json& j, const VolumeMeta& vm) {
  j = json{{"algorithms", vm.algorithms},
           {"key", vm.key},
           {"extent_size", vm.extent_size},
           {"extents", vm.extents}};
}
void bvm::to_json(json& j, const SlotMeta& meta) {
  j = json{{"version", meta.version}, {"volumes", meta.volumes}};
}

void bvm::from_json(const json& j, VolumeMeta& vm) {
  vm.algorithms = j["algorithms"].get<decltype(vm.algorithms)>();
  vm.key = j["key"].get<decltype(vm.key)>();
  vm.extent_size = j["extent_size"].get<decltype(vm.extent_size)>();
  vm.extents = j["extents"].get<decltype(vm.extents)>();
}
void bvm::from_json(const json& j, SlotMeta& meta) {
  meta.version = j["version"].get<decltype(meta.version)>();
  meta.volumes = j["volumes"].get<decltype(meta.volumes)>();
}

BVM::BVM(fs::path path) : path_{path}, fp_{}, size_{}, slots_{} {
  fp_.open(path, std::ios::binary | std::ios::in | std::ios::out);
  fp_.seekg(0, std::ios::end);
  size_ = fp_.tellg();
}

std::shared_ptr<Bootstrap> BVM::readBootstrap() {
  auto bootstrap = std::make_shared<Bootstrap>();
  Bootstrap& b = *bootstrap;
  fp_.seekg(0);
  fp_.read(reinterpret_cast<char*>(&b), sizeof(b));
  return bootstrap;
}

void BVM::writeBootstrap(const Bootstrap& bs) {
  fp_.seekp(0);
  fp_.write(reinterpret_cast<const char*>(&bs), sizeof(bs));
  fp_.flush();
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

  writeBootstrap(b);
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

uint8_t BVM::getFreeSlot() {
  if (slots_.size() >= MAX_SLOTS) {
    throw std::runtime_error("no more slots available in bootstrap");
  }
  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  uint8_t slotn = rng->next_byte() % (MAX_SLOTS - slots_.size());
  while (slots_.find(slotn) != slots_.end()) {
    slotn++;
  }

  return slotn;
}

SlotPtr BVM::createSlot(const std::string& passphrase,
                        const algorithms_type& algorithms) {
  if (slots_.size() >= MAX_SLOTS) {
    throw std::runtime_error("no more slots available in bootstrap");
  } else if (passphrase.empty()) {
    throw std::runtime_error("passphrase must not be empty");
  }

  auto slotn = getFreeSlot();
  auto slot = std::make_shared<Slot>(slotn, passphrase, algorithms);
  slots_[slotn] = slot;
  return slot;
}

SlotPtr BVM::createSlot(const salt_type& salt, const key_type& key,
                        const algorithms_type& algorithms) {
  if (slots_.size() >= MAX_SLOTS) {
    throw std::runtime_error("no more slots available in bootstrap");
  }
  auto slotn = getFreeSlot();
  auto slot = std::make_shared<Slot>(slotn, salt, key, algorithms);
  slots_[slotn] = slot;
  return slot;
}

void BVM::closeSlot(uint8_t slotn) { slots_.erase(slotn); }

SlotPtr BVM::unlockSlot(const std::string& passphrase) {
  if (slots_.size() >= MAX_SLOTS) {
    throw std::runtime_error("no more slots available in bootstrap");
  } else if (passphrase.empty()) {
    throw std::runtime_error("passphrase must not be empty");
  }

  auto bootstrap = readBootstrap();
  for (uint8_t slotn = 0; slotn < MAX_SLOTS; slotn++) {
    // already unlocked, skip
    if (slots_.find(slotn) != slots_.end()) {
      continue;
    }

    auto slot = Slot::deserialize(slotn, passphrase, bootstrap->slots[slotn]);
    if (slot != nullptr) {
      slots_[slotn] = slot;
      return slot;
    }
  }

  // failed to unlock
  return nullptr;
}

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
  writeBootstrap(b);
  return true;
}

Slot::Slot(uint8_t slotn, const salt_type& salt, const key_type& key,
           const algorithms_type& algorithms, SlotMeta meta)
    : slotn_{slotn},
      salt_{salt},
      iv_{},
      key_{key},
      meta_{meta},
      algorithms_{algorithms} {
  if (!algorithms_valid(algorithms_)) {
    throw std::runtime_error(
        "Invalid algorithms: {}"_format(fmt::join(algorithms_, ",")));
  }
}

Slot::Slot(uint8_t slotn, const std::string& passphrase,
           const algorithms_type& algorithms)
    : Slot(slotn, salt_type(), key_type(), algorithms) {
  setSalt();
  key_ = deriveKey(passphrase, salt_);
}

SlotPtr Slot::deserialize(uint8_t slotn, const std::string& passphrase,
                          const KeySlot& ks) {
  salt_type salt(&ks.salt[0], &ks.salt[0] + sizeof(ks.salt));
  auto key = deriveKey(passphrase, salt);
  return deserialize(slotn, key, ks);
}

SlotPtr Slot::deserialize(uint8_t slotn, const key_type& key,
                          const KeySlot& ks) {
  for (const auto& alg : VALID_ALGORITHMS) {
    auto slot = deserialize(slotn, key, ks, {alg});
    if (slot != nullptr) {
      return slot;
    }
  }
  return nullptr;
}

SlotPtr Slot::deserialize(uint8_t slotn, const key_type& key, const KeySlot& ks,
                          const algorithms_type& algorithms) {
  // load salt and iv
  salt_type salt(&ks.salt[0], &ks.salt[0] + sizeof(ks.salt));
  iv_type iv(&ks.iv[0], &ks.iv[0] + sizeof(ks.iv));

  // decrypt payload
  Botan::secure_vector<uint8_t> ctext(
      reinterpret_cast<const uint8_t*>(&ks.payload),
      reinterpret_cast<const uint8_t*>(&ks.payload) + sizeof(ks.payload));
  // iterate algorithms in reverse order
  for (auto alg = algorithms.crbegin(); alg != algorithms.crend(); alg++) {
    decrypt(*alg, key, iv, ctext);
  }

  // load payload
  KeySlotPayload& p = *(reinterpret_cast<KeySlotPayload*>(ctext.data()));

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

    // verify hash
    if (memcmp(p.sha256_checksum, hash.data(), hash.size()) != 0) {
      return nullptr;
    }
  }

  // deserialize meta from cbor
  if (p.data.meta_size > sizeof(p.data.meta)) {
    throw std::runtime_error(fmt::format(
        "deserialized meta size ({}) is invalid", p.data.meta_size));
  }

  SlotMeta meta =
      json::from_cbor(
          std::vector<uint8_t>(p.data.meta, p.data.meta + p.data.meta_size))
          .get<SlotMeta>();

  // finally
  return std::make_shared<Slot>(slotn, salt, key, algorithms, meta);
}

void Slot::serialize(KeySlot& ks) {
  // randomize iv if required
  if (iv_.size() != sizeof(ks.iv)) {
    auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
    iv_ = rng->random_vec(sizeof(ks.iv));
  }

  // copy salt and iv to keyslot
  memcpy(ks.salt, salt_.data(), salt_.size());
  memcpy(ks.iv, iv_.data(), iv_.size());

  // allocate memory for plaintext payload
  auto payload = std::make_unique<KeySlotPayload>();
  KeySlotPayload& p = *payload;
  memset(&p, 0, sizeof(p));

  // serialize meta to cbor
  std::vector<uint8_t> v_cbor = json::to_cbor(json(meta_));
  if (v_cbor.size() > sizeof(p.data.meta)) {
    throw std::runtime_error(
        "Metadata is too large ({}), needs to be smaller than: {}"_format(
            v_cbor.size(), sizeof(p.data.meta)));
  }

  // copy meta to payload
  p.data.meta_size = v_cbor.size();
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

void Slot::setSalt(size_t size) {
  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  setSalt(rng->random_vec(size));
}

void Slot::setIV(size_t size) {
  auto rng = std::make_unique<Botan::AutoSeeded_RNG>();
  setIV(rng->random_vec(size));
}

key_type Slot::deriveKey(const std::string& passphrase, const salt_type& salt,
                         size_t size) {
  auto argon = Botan::PasswordHashFamily::create("Argon2id");
  auto kdf = argon->default_params();
  auto key = key_type(size, 0);
  kdf->derive_key(key.data(), key.size(), passphrase.c_str(),
                  passphrase.length(), salt.data(), salt.size());
  return key;
}

bool Slot::algorithms_valid(const algorithms_type& algorithms) {
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

void Slot::encrypt(const std::string& algorithm, const key_type& key,
                   const iv_type& iv, Botan::secure_vector<uint8_t>& ctext) {
  auto enc = Botan::Cipher_Mode::create(algorithm, Botan::ENCRYPTION);
  if (iv.size() < enc->default_nonce_length()) {
    throw std::runtime_error(
        "Invalid iv size: {}"_format(enc->default_nonce_length()));
  }
  enc->set_key(key);
  // only use what we need from the iv
  enc->start(iv_type(iv.begin(), iv.begin() + enc->default_nonce_length()));
  enc->finish(ctext);
}

void Slot::decrypt(const std::string& algorithm, const key_type& key,
                   const iv_type& iv, Botan::secure_vector<uint8_t>& ctext) {
  auto enc = Botan::Cipher_Mode::create(algorithm, Botan::DECRYPTION);
  if (iv.size() < enc->default_nonce_length()) {
    throw std::runtime_error(
        "Invalid iv size: {}"_format(enc->default_nonce_length()));
  }
  enc->set_key(key);
  // enc->start(iv);
  enc->start(iv_type(iv.begin(), iv.begin() + enc->default_nonce_length()));
  enc->finish(ctext);
}
