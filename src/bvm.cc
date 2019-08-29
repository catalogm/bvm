/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include "bvm/bvm.hh"

#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hash.h>
#include <botan/pwdhash.h>
#include <algorithm>
#include <exception>
#include <iterator>
#include <sstream>
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
using bvm::SlotPtr;

// static disk format asserts
HEDLEY_STATIC_ASSERT(std::is_pod<Bootstrap>::value,
                     "bvm::Bootstrap must be a POD data type");

BVM::BVM(fs::path path) : path_{path}, fp_{}, size_{}, slots_{}, bitmap_{} {
  if (path_.string().find_first_of(" ") != std::string::npos) {
    throw std::runtime_error("path must not contain spaces");
  }
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

void BVM::closeSlot(uint8_t slotn) {
  auto slot = slots_.at(slotn);
  for (auto& vol : slot->volumes()) {
    for (auto& extn : vol.extents) {
      bitmap_.remove(extn);
    }
  }
  slots_.erase(slotn);
}

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
      // add extents to bitmap
      for (auto& vol : slot->volumes()) {
        for (auto& extn : vol.extents) {
          if (!bitmap_.addChecked(extn)) {
            throw std::runtime_error("Bitmap for slot already exists");
          }
        }
      }
      slots_[slotn] = slot;
      return slot;
    }
  }

  // failed to unlock
  return nullptr;
}

SlotPtr BVM::unlockSlot(const key_type& key) {
  if (slots_.size() >= MAX_SLOTS) {
    throw std::runtime_error("no more slots available in bootstrap");
  } else if (key.empty()) {
    throw std::runtime_error("key must not be empty");
  }

  auto bootstrap = readBootstrap();
  for (uint8_t slotn = 0; slotn < MAX_SLOTS; slotn++) {
    // already unlocked, skip
    if (slots_.find(slotn) != slots_.end()) {
      continue;
    }

    auto slot = Slot::deserialize(slotn, key, bootstrap->slots[slotn]);
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

uint64_t BVM::getRandomExtent(Botan::AutoSeeded_RNG& rng) {
  // get offset
  uint64_t offset = 0;
  {
    auto avail = extents_free();
    do {
      rng.randomize(reinterpret_cast<uint8_t*>(&offset), sizeof(offset));
    } while (offset >= (UINT64_MAX - UINT64_MAX % avail));
    offset = offset % avail;
  }

  auto total = extents_total();
  size_t skipped = 0;
  for (uint64_t extn = 0; extn < total; extn++) {
    if (bitmap_.contains(extn)) {
      continue;
    } else if (skipped < offset) {
      skipped++;
      continue;
    }
    return extn;
  }

  throw std::runtime_error("Failed to get random extent");
}

void BVM::addVolume(uint8_t slotn, size_t nextents, std::vector<Layer> layers) {
  if (layers.empty()) {
    throw std::runtime_error("layers size must be greater than 1");
  } else if (extents_free() < nextents) {
    throw std::runtime_error(
        "Not enough free extents ({}) for volume of size {}."_format(
            extents_free(), nextents));
  }

  auto& slot = slots_.at(slotn);

  Volume vol;
  vol.layers = std::move(layers);
  if (vol.layers.empty()) {
    vol.addLayer("aes-xts-plain64", 512 / 8);
  }
  vol.extent_size = extent_size();

  // allocate extents
  Botan::AutoSeeded_RNG rng;
  vol.extents.reserve(nextents);
  for (uint64_t i = 0; i < nextents; i++) {
    auto extn = getRandomExtent(rng);
    bitmap_.add(extn);
    vol.extents.push_back(extn);
  }

  slot->addVolume(std::move(vol));
}

void BVM::removeVolume(uint8_t slotn, uint64_t volumen) {
  auto& slot = slots_.at(slotn);
  auto& volumes = slot->volumes();
  if (volumen > volumes.size()) {
    throw std::runtime_error(fmt::format(
        "Volumen number({}) is greater than number of volumes({}) in slot({})",
        volumen, volumes.size(), slotn));
  }
  auto& vol = volumes[volumen];
  for (auto& extn : vol.extents) {
    bitmap_.remove(extn);
  }
  slot->removeVolume(volumen);
}

std::string BVM::conciseDeviceMapper(uint8_t slotn, uint64_t volumen,
                                     const std::string& name, bool rw) {
  // device mapper sector size, 512 bytes
  static constexpr size_t sector_size = 512;
  static_assert((EXTENT_SIZE % sector_size) == 0,
                "EXTENT_SIZE must be divisible by sector size of 512");

  const auto& slot = slots_.at(slotn);
  const auto& vol = slot->volumes().at(volumen);
  const auto& extents = vol.extents;
  const auto flags = rw ? "rw" : "ro";

  if (vol.layers.empty()) {
    throw std::runtime_error("Volume must contain at least one layer");
  }

  if (extents.size() < 1) {
    throw std::runtime_error("Volume must have at least 1 extent");
  }

  std::ostringstream buf;

  // create linear target
  std::string dev_name = fmt::format("bvm_linear_{}", name);
  buf << fmt::format("{},,,{}", dev_name, flags);
  auto sectors = vol.extent_size / sector_size;
  size_t start = 0;
  for (auto& extn : extents) {
    // offset within original file
    auto offset = bootstrap_size() + ((extn * vol.extent_size) / sector_size);

    // create table
    buf << fmt::format(",{start} {sectors} linear {path} {offset}",
                       "start"_a = start, "sectors"_a = sectors,
                       "path"_a = path_.string(), "offset"_a = offset);
    start += sectors;
  }

  // create encryption tables
  const auto& layers = vol.layers;
  auto total_sectors = start;
  auto last = layers.cend() - 1;
  auto count = 1;
  for (auto it = layers.cbegin(); it != layers.cend(); it++) {
    auto prev_dev_path = fmt::format("/dev/mapper/{}", dev_name);
    if (it != last) {
      dev_name = fmt::format("bvm_crypt_{0}_{1}", name, count);
      count++;
    } else {
      // last encryption as final table
      dev_name = name;
    }
    buf << fmt::format(
        ";{dev_name},,,{flags},0 {sectors} crypt {cipher} {key} 0 {dev} 0",
        "dev_name"_a = dev_name, "flags"_a = flags, "sectors"_a = total_sectors,
        "cipher"_a = (*it).cipher, "key"_a = fmt::join((*it).key, ""),
        "dev"_a = prev_dev_path);
  }

  return buf.str();
}

