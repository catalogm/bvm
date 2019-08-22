/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */
#ifndef INCLUDE_BVM_BVM_HH_
#define INCLUDE_BVM_BVM_HH_

#define FMT_STRING_ALIAS 1
#include <fmt/format.h>
#include <fmt/ostream.h>

#include <botan/secmem.h>
#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

#include "nlohmann/json.hpp"
#include "roaring/roaring.hh"

namespace bvm {

namespace fs = std::filesystem;
using json = nlohmann::json;

#pragma pack(push, 1)
struct KeySlotPayload {
  uint8_t sha256_checksum[32];
  struct {
    uint8_t meta[1024 * 1024];  // cbor data
    uint8_t _reserved1[16];
    uint8_t _reserved2[128];
  } data;
  /*
  {
    "version": [],
    "key": [], // 64 bytes
    "volumes": [{
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

class Slot {
 public:
  using salt_type = Botan::secure_vector<uint8_t>;
  using key_type = Botan::secure_vector<uint8_t>;
  using iv_type = Botan::secure_vector<uint8_t>;

  static inline const std::vector<std::string> VALID_ALGORITHMS = {
      "AES-256/XTS",
      "Twofish/XTS",
      "Serpent/XTS",
  };

  ~Slot() = default;
  Slot() = default;
  explicit Slot(uint8_t slotn, salt_type salt, key_type key,
                std::vector<std::string> algorithms = {"AES-256/XTS"});

  static bool algorithms_valid(const std::vector<std::string>& algorithms);
  static void encrypt(const std::string& algorithm,
                      const Botan::secure_vector<uint8_t>& key,
                      const Botan::secure_vector<uint8_t>& iv,
                      Botan::secure_vector<uint8_t>& ctext);
  static void decrypt(const std::string& algorithm,
                      const Botan::secure_vector<uint8_t>& key,
                      const Botan::secure_vector<uint8_t>& iv,
                      Botan::secure_vector<uint8_t>& ctext);

  void serialize(KeySlot& ks);

  uint8_t slotn() { return slotn_; }
  salt_type salt() { return salt_; }
  iv_type iv() { return iv_; }
  key_type key() { return key_; }
  json meta() { return meta_; }
  std::vector<std::string> algorithms() { return algorithms_; }

 private:
  uint8_t slotn_;
  salt_type salt_;
  iv_type iv_;
  key_type key_;
  json meta_;
  std::vector<std::string> algorithms_;
};
using SlotPtr = std::shared_ptr<Slot>;

class BVM {
 public:
  using ptr_type = std::shared_ptr<BVM>;
  using slots_type = std::map<int, SlotPtr>;

  ~BVM() = default;
  BVM() = delete;
  explicit BVM(fs::path path);

  bool wipe(bool magic = false);
  bool wipeBootstrap(bool magic = false);
  bool wipeData(uint64_t blocksize = 4096);

  SlotPtr createSlot(std::string passphrase);
  SlotPtr createSlot(Botan::secure_vector<uint8_t> salt,
                     Botan::secure_vector<uint8_t> key);
  /*
  SlotPtr unlockSlot(std::string passphrase);
  SlotPtr unlockSlot(Botan::secure_vector<uint8_t> salt,
                     Botan::secure_vector<uint8_t> key);
                     */
  bool writeSlot(uint8_t slotn);

  const uint64_t& size() const noexcept { return size_; }
  const fs::path& path() const noexcept { return path_; }
  size_t slots_size() const noexcept { return slots_.size(); }
  slots_type slots() const noexcept { return slots_; }

  friend std::ostream& operator<<(std::ostream& os, const BVM& b) {
    return os << fmt::format("BVM(path={})", b.path());
  }

  static inline std::string MAGIC_HEADER = "BVM";
  static inline constexpr size_t MAX_SLOTS = 16;

 private:
  fs::path path_;
  std::fstream fp_;
  uint64_t size_;
  slots_type slots_;
};

using BVMPtr = BVM::ptr_type;

}  // namespace bvm
#endif  // INCLUDE_BVM_BVM_HH_
