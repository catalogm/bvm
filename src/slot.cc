/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include "bvm/slot.hh"

#define FMT_STRING_ALIAS 1
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/pwdhash.h>
#include <fmt/format.h>
#include <fmt/ostream.h>

using bvm::key_type;
using bvm::Layer;
using bvm::Slot;
using bvm::SlotPtr;
using bvm::Volume;
using json = nlohmann::json;
using namespace fmt::literals;

void bvm::to_json(json& j, const Slot& slot) {
  j = json{{"version", BVM_DISK_FORMAT_VERSION}, {"volumes", slot.volumes()}};
}

void bvm::to_json(json& j, const Volume& v) {
  j = json{{"layers", v.layers},
           {"extent_size", v.extent_size},
           {"extents", v.extents}};
}

void bvm::to_json(json& j, const Layer& l) {
  j = json{{"cipher", l.cipher}, {"key", l.key}};
}

void bvm::from_json(const json& j, Slot& slot) {
  using VolumeVec = std::vector<Volume>;
  slot.setVolumes(j["volumes"].get<VolumeVec>());
}

void bvm::from_json(const json& j, Volume& v) {
  j.at("layers").get_to(v.layers);
  j.at("extent_size").get_to(v.extent_size);
  j.at("extents").get_to(v.extents);
}

void bvm::from_json(const json& j, Layer& l) {
  j.at("cipher").get_to(l.cipher);
  j.at("key").get_to(l.key);
}

Layer& Volume::addLayer(std::string cipher, size_t key_size) {
  Botan::AutoSeeded_RNG rng;
  layers.emplace_back(cipher, rng.random_vec(key_size));
  return layers.back();
}

Slot::Slot(uint8_t slotn, const salt_type& salt, const key_type& key,
           const algorithms_type& algorithms)
    : slotn_{slotn},
      salt_{salt},
      iv_{},
      key_{key},
      algorithms_{algorithms},
      volumes_{} {
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

void Slot::addVolume(Volume volume) { volumes_.push_back(std::move(volume)); }

void Slot::removeVolume(uint64_t volumen) {
  volumes_.erase(volumes_.begin() + volumen);
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

  auto slot = std::make_shared<Slot>(slotn, salt, key, algorithms);
  auto&& cbor = json::from_cbor(
      std::vector<uint8_t>(p.data.meta, p.data.meta + p.data.meta_size));
  cbor.get_to(*slot);

  // finally
  return slot;
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
  std::vector<uint8_t> v_cbor = json::to_cbor(json(*this));
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
