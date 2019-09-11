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

#include "bvm/disk.hh"
#include "bvm/slot.hh"
#include "nlohmann/json.hpp"
#include "roaring64map.hh"

namespace bvm {

namespace fs = std::filesystem;

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
                 std::vector<Layer> layers = {});
  void removeVolume(uint8_t slotn, uint64_t volumen);
  std::string conciseDeviceMapper(uint8_t slotn, uint64_t volumen,
                                  const std::string& name, bool rw = true);

  const uint64_t& size() const noexcept { return size_; }
  constexpr uint64_t bootstrap_size() const noexcept {
    return sizeof(Bootstrap);
  }
  uint64_t data_size() const noexcept { return size_ - bootstrap_size(); }
  const fs::path& path() const noexcept { return path_; }

  slots_type slots() const noexcept { return slots_; }
  size_t slots_total() const noexcept { return MAX_SLOTS; }
  size_t slots_used() const noexcept { return slots_.size(); }

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
  static inline constexpr size_t MAX_SLOTS = BVM_DISK_MAX_SLOTS;

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
