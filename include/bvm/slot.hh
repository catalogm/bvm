/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */
#ifndef INCLUDE_BVM_SLOT_HH_
#define INCLUDE_BVM_SLOT_HH_

#include <botan/secmem.h>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "bvm/disk.hh"
#include "nlohmann/json.hpp"

namespace bvm {

using json = nlohmann::json;

// Types
using salt_type = Botan::secure_vector<uint8_t>;
using key_type = Botan::secure_vector<uint8_t>;
using iv_type = Botan::secure_vector<uint8_t>;
using algorithms_type = std::vector<std::string>;

static constexpr size_t DEFAULT_EXTENT_SIZE = 1024 * 1024 * 1024;
static inline const algorithms_type VALID_ALGORITHMS = {
    "AES-256/XTS",
    "Twofish/XTS",
    "Serpent/XTS",
};

static inline const algorithms_type DEFAULT_ALGORITHMS = {"AES-256/XTS"};

struct Layer {
  std::string cipher;
  key_type key;

  ~Layer() = default;
  Layer() : cipher{}, key{} {}
  Layer(std::string c, key_type k) : cipher{c}, key{k} {}
  Layer(std::string c, size_t key_size);
};

struct Volume {
  std::vector<Layer> layers;
  uint64_t extent_size = DEFAULT_EXTENT_SIZE;
  std::vector<uint64_t> extents;

  Layer& addLayer(std::string cipher, size_t key_size);
};

class Slot {
 public:
  using ptr_type = std::shared_ptr<Slot>;

  ~Slot() = default;
  Slot() = default;
  Slot(uint8_t slotn, const std::string& passphrase,
       const algorithms_type& algorithms = DEFAULT_ALGORITHMS);
  Slot(uint8_t slotn, const salt_type& salt, const key_type& key,
       const algorithms_type& algorithms = DEFAULT_ALGORITHMS);

  void serialize(KeySlot& ks);
  static ptr_type deserialize(uint8_t slotn, const std::string& passphrase,
                              const KeySlot& ks);
  static ptr_type deserialize(uint8_t slotn, const key_type& key,
                              const KeySlot& ks);
  static ptr_type deserialize(uint8_t slotn, const key_type& key,
                              const KeySlot& ks,
                              const algorithms_type& algorithms);

  inline void setKey(const std::string& passphrase) {
    setKey(deriveKey(passphrase, salt_));
  }
  void setKey(key_type key) { key_ = std::move(key); }

  void setSalt(size_t size = sizeof(KeySlot::salt));
  void setSalt(salt_type salt) { salt_ = std::move(salt); }

  void setIV(size_t size = sizeof(KeySlot::iv));
  void setIV(iv_type iv) { iv_ = std::move(iv); }

  uint8_t slotn() const { return slotn_; }
  salt_type salt() const { return salt_; }
  iv_type iv() { return iv_; }
  key_type key() { return key_; }
  algorithms_type algorithms() { return algorithms_; }

  const std::vector<Volume>& volumes() const { return volumes_; }
  void setVolumes(std::vector<Volume> vols) { volumes_ = std::move(vols); }

  static key_type deriveKey(
      const std::string& passphrase, const salt_type& salt,
      size_t size = 512 / 8 /* multipley by 3 on next botan release * 3 */);

  static bool algorithms_valid(const algorithms_type& algorithms);
  static void encrypt(const std::string& algorithm, const key_type& key,
                      const iv_type& iv, Botan::secure_vector<uint8_t>& ctext);
  static void decrypt(const std::string& algorithm, const key_type& key,
                      const iv_type& iv, Botan::secure_vector<uint8_t>& ctext);

  friend class BVM;

 protected:
  void addVolume(Volume volume);
  void removeVolume(uint64_t volumen);

 private:
  uint8_t slotn_;
  salt_type salt_;
  iv_type iv_;
  key_type key_;
  algorithms_type algorithms_;
  std::vector<Volume> volumes_;
};
using SlotPtr = std::shared_ptr<Slot>;

void to_json(json& j, const Slot& slot);
void to_json(json& j, const Volume& v);
void to_json(json& j, const Layer& l);
void from_json(const json& j, Slot& slot);
void from_json(const json& j, Volume& v);
void from_json(const json& j, Layer& l);

};      // namespace bvm
#endif  // INCLUDE_BVM_SLOT_HH_
