/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */
#ifndef INCLUDE_BVM_BVM_HH_
#define INCLUDE_BVM_BVM_HH_

#define FMT_STRING_ALIAS 1
#include <fmt/format.h>
#include <fmt/ostream.h>

#include <botan/auto_rng.h>
#include <botan/secmem.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <utility>
#include <vector>

#include "nlohmann/json.hpp"
#include "roaring64map.hh"

namespace bvm {

namespace fs = std::filesystem;
using json = nlohmann::json;

#define BVM_DISK_FORMAT_VERSION 0

#pragma pack(push, 1)
struct KeySlotPayload {
  uint8_t sha256_checksum[32];
  struct {
    uint32_t meta_size;
    uint8_t meta[1024 * 1024];  // cbor data
    uint8_t _reserved1[16];
    uint8_t _reserved2[96];
  } data;
  /*
  {
    "version": 0,
    "volumes": [{
      "key": "", // 64 bytes
      "algorithms": ["aes-xts-plain64"],
      "extent_size": 1024 * 1024 * 1024
      "extents": [1, 2, 3],
    }],
  }
  */
};

struct KeySlot {
  uint8_t salt[32];  // used for argon2id
  uint8_t iv[32];    // used for key iv
  // encrypted with chosen algorithm
  KeySlotPayload payload;
};

struct Bootstrap {
  char magic[5];
  KeySlot slots[16];
  uint8_t _reserved[251];
};
#pragma pack(pop)

// POD operators
bool operator<(const KeySlot& lhs, const KeySlot& rhs);
bool operator==(const KeySlot& lhs, const KeySlot& rhs);

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

struct VolumeMeta {
  std::vector<std::string> algorithms;
  key_type key;
  uint64_t extent_size = DEFAULT_EXTENT_SIZE;
  std::vector<uint64_t> extents;
};

struct SlotMeta {
  uint8_t version = BVM_DISK_FORMAT_VERSION;
  std::vector<VolumeMeta> volumes;
};

void to_json(json& j, const VolumeMeta& vm);
void to_json(json& j, const SlotMeta& meta);
void from_json(const json& j, VolumeMeta& vm);
void from_json(const json& j, SlotMeta& meta);

/*
class Volume {
 public:
  ~Volume() = default;
  Volume() = default;

 private:
  algorithms_type algorithms_;
  uint64_t extent_size_;
  std::vector<uint64_t> extents_;
};
*/

class Slot {
 public:
  using ptr_type = std::shared_ptr<Slot>;

  ~Slot() = default;
  Slot() = default;
  Slot(uint8_t slotn, const std::string& passphrase,
       const algorithms_type& algorithms = DEFAULT_ALGORITHMS);
  Slot(uint8_t slotn, const salt_type& salt, const key_type& key,
       const algorithms_type& algorithms = DEFAULT_ALGORITHMS,
       SlotMeta meta = SlotMeta{});

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

  uint8_t slotn() { return slotn_; }
  salt_type salt() { return salt_; }
  iv_type iv() { return iv_; }
  key_type key() { return key_; }
  const SlotMeta& meta() { return meta_; }
  const std::vector<VolumeMeta>& volumes() { return meta_.volumes; }
  algorithms_type algorithms() { return algorithms_; }

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
  void addVolume(VolumeMeta volume);
  void removeVolume(uint64_t volumen);

 private:
  uint8_t slotn_;
  salt_type salt_;
  iv_type iv_;
  key_type key_;
  SlotMeta meta_;
  algorithms_type algorithms_;
};
using SlotPtr = std::shared_ptr<Slot>;

class BVM {
 public:
  using ptr_type = std::shared_ptr<BVM>;
  using slots_type = std::map<uint8_t, SlotPtr>;

  ~BVM() = default;
  BVM() = delete;
  explicit BVM(fs::path path);

  uint8_t getFreeSlot();
  std::shared_ptr<Bootstrap> readBootstrap();
  void writeBootstrap(const Bootstrap& bs);

  bool wipe(bool magic = false);
  bool wipeBootstrap(bool magic = false);
  bool wipeData(uint64_t blocksize = 4096);

  SlotPtr createSlot(const std::string& passphrase,
                     const algorithms_type& algorithms = DEFAULT_ALGORITHMS);
  SlotPtr createSlot(const salt_type& salt, const key_type& key,
                     const algorithms_type& algorithms = DEFAULT_ALGORITHMS);

  void closeSlot(uint8_t slotn);

  SlotPtr unlockSlot(const std::string& passphrase);
  SlotPtr unlockSlot(const key_type& key);

  bool writeSlot(uint8_t slotn);

  uint64_t getRandomExtent(Botan::AutoSeeded_RNG& rng);
  void addVolume(uint8_t slotn, uint64_t nextents,
                 algorithms_type algorithms = {"aes-xts-essiv:sha256"});
  void removeVolume(uint8_t slotn, uint64_t volumen);
  std::string conciseDeviceMapper(uint8_t slotn, uint64_t volumen,
                                  const std::string& name, bool rw = true);

  const uint64_t& size() const noexcept { return size_; }
  constexpr uint64_t bootstrap_size() const noexcept {
    return sizeof(Bootstrap);
  }
  uint64_t data_size() const noexcept { return size_ - bootstrap_size(); }
  const fs::path& path() const noexcept { return path_; }
  size_t slots_size() const noexcept { return slots_.size(); }
  slots_type slots() const noexcept { return slots_; }

  constexpr uint64_t extent_size() const noexcept { return EXTENT_SIZE; }
  uint64_t extents_total() const { return data_size() / extent_size(); }
  uint64_t extents_used() const {
    return std::min(bitmap_.cardinality(), extents_total());
  }
  uint64_t extents_free() const {
    return std::max(uint64_t{0}, extents_total() - extents_used());
  }

  friend std::ostream& operator<<(std::ostream& os, const BVM& b) {
    return os << fmt::format("BVM(path={})", b.path());
  }

  static inline const std::string MAGIC_HEADER = "BVM";
  static inline constexpr size_t MAX_SLOTS = 16;

  // min extent size of 1 gigabyte
  static inline constexpr size_t EXTENT_SIZE = DEFAULT_EXTENT_SIZE;

 private:
  fs::path path_;
  std::fstream fp_;
  uint64_t size_;
  slots_type slots_;
  Roaring64Map bitmap_;
};

using BVMPtr = BVM::ptr_type;

}  // namespace bvm
#endif  // INCLUDE_BVM_BVM_HH_
