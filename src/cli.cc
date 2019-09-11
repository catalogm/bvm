/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#define FMT_STRING_ALIAS 1
#include <fmt/format.h>
#include <fmt/ostream.h>

#include <botan/hex.h>
#include <botan/pwdhash.h>
#include <libdevmapper.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <termios.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cassert>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <iterator>
#include <memory>
#include <regex>
#include <sstream>
#include <string>
#include <thread>
#include <tuple>
#include <utility>
#include <vector>

#include "bvm/bvm.hh"
#include "bvm/cli.hh"
#include "replxx.hxx"

#if !(defined(BVM_VERSION_MAJOR) && defined(BVM_VERSION_MINOR) && \
      defined(BVM_VERSION_PATCH))
#error "BVM_VERSION_* must be defined"
#endif

using namespace fmt::literals;
namespace fs = std::filesystem;
using bvm::BVM;
using bvm::Layer;
using replxx::Replxx;

struct GlobalOptions {
  fs::path path;
};
using GlobalOptionsPtr = std::shared_ptr<GlobalOptions>;

template <class... Types>
class Table {
 public:
  using tuple_type = std::tuple<Types...>;
  static constexpr auto num_columns = std::tuple_size<tuple_type>::value;

  explicit Table(std::vector<std::string> headers)
      : headers_{headers}, rows_{} {
    assert(headers.size() == num_columns);
  }

  void addRow(Types... vals) { addRow(std::make_tuple(vals...)); }
  void addRow(tuple_type data) { rows_.push_back(data); }

  template <size_t I = 0>
  void printRow(const std::array<size_t, num_columns>& sizes,
                const tuple_type& row) {
    fmt::print("{:>{}} ", std::get<I>(row), sizes[I]);
    if constexpr (I + 1 != num_columns) {
      printRow<I + 1>(sizes, row);
    } else {
      fmt::print("\n");
    }
  }

  void print(bool withHeader = true) {
    auto sizes = getColumnSizes();
    if (withHeader) {
      for (size_t i = 0; i < num_columns; i++) {
        fmt::print("{:<{}} ", headers_[i], sizes[i]);
      }
      fmt::print("\n");
    }
    for (const auto& row : rows_) {
      printRow(sizes, row);
    }
  }

  template <size_t I = 0>
  void getColSizes(std::array<size_t, num_columns>& sizes,
                   const tuple_type& row) {
    sizes[I] = std::max(fmt::formatted_size("{}", std::get<I>(row)), sizes[I]);
    if constexpr (I + 1 != num_columns) {
      getColSizes<I + 1>(sizes, row);
    }
  }

  std::array<size_t, num_columns> getColumnSizes() {
    std::array<size_t, num_columns> sizes;
    for (size_t i = 0; i < headers_.size(); i++) {
      sizes[i] = headers_[i].length();
    }
    for (const auto& row : rows_) {
      getColSizes(sizes, row);
    }
    return sizes;
  }

 private:
  std::vector<std::string> headers_;
  std::vector<tuple_type> rows_;
};

inline void register_version_command(CLI::App& app) {
  auto callback = []() {
    std::cout << "bvm version {}.{}.{}{}"_format(BVM_VERSION_MAJOR,
                                                 BVM_VERSION_MINOR,
                                                 BVM_VERSION_PATCH, "")
              // BVM_VERSION_TWEAK ? ".{}"_format(BVM_VERSION_TWEAK) : "")
              << std::endl;
    std::exit(EXIT_SUCCESS);
  };
  app.add_flag_callback("--version,-V", std::move(callback),
                        "Print version info and exit");

  CLI::App* sub = app.add_subcommand("test-argon");
  struct Options {
    std::vector<std::string> ciphers = {"aes-xts-plain64"};
  };
  auto opts = std::make_shared<Options>();
  sub->add_option("ciphers", opts->ciphers, "ciphers to test and print", true);
  sub->callback([opts]() {
    auto log = spdlog::get("bvm.cli");
    log->debug("testing ciphers: {}", fmt::join(opts->ciphers, ", "));

    using bvm::key_type;

    size_t iter = 16;
    size_t mem = 256 * 1024;  // memory used in kilobytes
    size_t para = 8;
    size_t key_size = 512 / 8;
    log->debug("testing argon2id");
    auto argon = Botan::PasswordHashFamily::create("Argon2id");
    auto kdf = argon->from_params(mem, iter, para);
    auto key = key_type(key_size, 0);
    auto salt = key_type(32, 0);
    std::string passphrase = "hello world";

    using Clock = std::chrono::steady_clock;
    using std::chrono::time_point;
    using std::chrono::duration_cast;
    using std::chrono::milliseconds;

    time_point<Clock> start = Clock::now();
    {
      kdf->derive_key(key.data(), key.size(), passphrase.c_str(),
                      passphrase.length(), salt.data(), salt.size());
      time_point<Clock> end = Clock::now();
      milliseconds diff = duration_cast<milliseconds>(end - start);
      log->info("{} takes: {} ms", kdf->to_string(), diff.count());
    }

    /*
    {
      // Test: https://github.com/P-H-C/phc-winner-argon2
      std::string salt_string = "somesalt";
      key.resize(24);
      salt = key_type(salt_string.begin(), salt_string.end());
      passphrase = "password";
      argon = Botan::PasswordHashFamily::create("Argon2i");
      kdf = argon->from_params(65536, 2, 4);

      start = Clock::now();
      kdf->derive_key(key.data(), key.size(), passphrase.c_str(),
                      passphrase.length(), salt.data(), salt.size());
      time_point<Clock> end = Clock::now();
      milliseconds diff = duration_cast<milliseconds>(end - start);
      log->info("{} takes: {} ms", kdf->to_string(), diff.count());
      log->info("hash: {}", Botan::hex_encode(key));
      log->info("equal: {}",
                Botan::hex_decode(
                    "45d7ac72e76f242b20b77b9bf9bf9d5915894e669a24e6c6") ==
                    std::vector<uint8_t>(key.begin(), key.end()));
    }
    */
  });
}

std::string prompt_passphrase(std::string prompt = "Enter password: ") {
  std::string passphrase;
  termios oldt;
  tcgetattr(STDIN_FILENO, &oldt);
  termios newt = oldt;
  newt.c_lflag &= ~ECHO;
  tcsetattr(STDIN_FILENO, TCSANOW, &newt);

  std::cout << prompt;
  std::cout.flush();
  std::getline(std::cin, passphrase);
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
  std::cout << std::endl;
  return passphrase;
}

inline void register_shell_command(CLI::App& app) {
  CLI::App* sub = app.add_subcommand("shell", "Open bvm shell");
  struct Options {
    std::string path;
  };
  auto opts = std::make_shared<Options>();

  sub->add_option("path", opts->path, "book volume path")
      ->check(CLI::ExistingFile)
      ->required();

  sub->callback([opts]() {
    auto log = spdlog::get("bvm.cli");
    log->debug("path = '{}'", opts->path);

    BVM bvm(opts->path);
    log->debug("bvm = {}", bvm);

    Replxx rx;
    rx.install_window_change_handler();
    rx.set_max_history_size(128);
    rx.set_max_hint_rows(3);

    rx.set_highlighter_callback(
        [](std::string const& context, Replxx::colors_t& colors) {
          using cl = Replxx::Color;
          static const std::vector<std::pair<std::string, cl>> regex_color{
              // commands
              {"^(help|exit|(q|quit)|clear|history)$", cl::BRIGHTMAGENTA},
              {"^(p|print)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(ps|print-slots?)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(pv|print-volumes?)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(pm|print-maps?)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(pms|print-map-slot)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(pmd|print-map-data)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(ns|new-slot)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(u|unlock)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(l|lock)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(w|write|save)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(mkn|mknode)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^(rmn|rmnode)( .*?)?$", cl::BRIGHTMAGENTA},
              {"^wipe-slot( .*?)?$", cl::BRIGHTMAGENTA},
              {"^wipe-header$", cl::BRIGHTMAGENTA},
              {"^wipe-data$", cl::BRIGHTMAGENTA},
              {"^wipe-volume( .*?)?$", cl::BRIGHTMAGENTA},
              {"^wipe-all$", cl::BRIGHTMAGENTA},
          };

          // highlight matching regex sequences
          for (auto const& e : regex_color) {
            size_t pos{0};
            std::string str = context;
            std::smatch match;

            while (std::regex_search(str, match, std::regex(e.first))) {
              std::string c{match[0]};
              std::string prefix(match.prefix().str());
              pos += prefix.length();
              int len = c.length();
              for (int i = 0; i < len; ++i) {
                colors.at(pos + i) = e.second;
              }

              pos += len;
              str = match.suffix();
            }
          }
        });

    rx.set_word_break_characters(" \t.,-%!;:=*~^'\"/?<>|[](){}");
    rx.set_completion_count_cutoff(128);
    rx.set_double_tab_completion(false);
    rx.set_complete_on_empty(true);
    rx.set_beep_on_ambiguous_completion(false);
    rx.set_no_color(false);

    using std::placeholders::_1;
    rx.bind_key(
        Replxx::KEY::UP,
        std::bind(&Replxx::invoke, &rx, Replxx::ACTION::HISTORY_PREVIOUS, _1));
    rx.bind_key(Replxx::KEY::DOWN, std::bind(&Replxx::invoke, &rx,
                                             Replxx::ACTION::HISTORY_NEXT, _1));
    rx.bind_key(Replxx::KEY::control('D'),
                std::bind(&Replxx::invoke, &rx, Replxx::ACTION::SEND_EOF, _1));

    std::cout << "Welcome to bvm\n"
              << "Press 'tab' to view autocompletions\n"
              << "Type 'help' for help\n"
              << "Type 'quit' or 'exit' to exit\n\n";
    std::string prompt = {"\x1b[1;32mbvm\x1b[0m> "};

    std::map<uint8_t, bool> dirtySlots;

    for (;;) {
      char const* cinput{nullptr};
      do {
        cinput = rx.input(prompt);
      } while ((cinput == nullptr) && (errno == EAGAIN));

      if (cinput == nullptr) {
        break;
      }

      std::string input{cinput};

      if (input.empty()) {
        continue;
      }

      rx.history_add(input);
      if (input == "q" || input == "quit" || input == "exit") {
        break;
      } else if (input == "clear") {
        rx.clear_screen();
      } else if (input == "help") {
        std::cout << "help\n  displays this help output\n"
                  << "q|quit\n  exit the shell\n"
                  << "exit\n  exit the shell\n"
                  << "clear\n  clears the screen\n"
                  << "history\n  displays the history output\n";
      } else if (input == "history") {
        for (size_t i = 0, sz = rx.history_size(); i < sz; ++i) {
          fmt::print("{:>4}: {}\n", i, rx.history_line(i));
        }
      } else if (input == "p" || input == "print") {
        constexpr size_t gb = 1024 * 1024 * 1024;
        fmt::print(("Disk {path}: {size} GB\n  bootstrap header: "
                    "{bootstrap_size} bytes\n  data: {data_size} GB\n"
                    "  extent size: {extent_size} GB\n"
                    "  extents: {extents_used} / {extents_total}\n"
                    "\n"),
                   "path"_a = fs::absolute(bvm.path()).string(),
                   "size"_a = bvm.size() / gb,
                   "bootstrap_size"_a = bvm.bootstrap_size(),
                   "data_size"_a = bvm.extents_total() * bvm.extent_size() / gb,
                   "extent_size"_a = bvm.extent_size() / gb,
                   "extents_used"_a = bvm.extents_used(),
                   "extents_total"_a = bvm.extents_total());

        fmt::print("Slots: {} / {}\n", bvm.slots_used(), bvm.slots_total());
        if (bvm.slots_used() > 0) {
          {
            Table<uint8_t, size_t, size_t> tbl({"Slot", "Volumes", "Size(gb)"});
            for (const auto& [slotn, slot] : bvm.slots()) {
              size_t size = 0;
              for (const auto& v : slot->volumes()) {
                size += v.extent_size * v.extents.size();
              }
              tbl.addRow(slotn, slot->volumes().size(), size / gb);
            }
            tbl.print();
            fmt::print("\n");
          }

          Table<uint8_t, size_t, std::string, size_t, size_t> tbl(
              {"Slot", "Vol #", "Name", "Layers", "Size(gb)"});
          for (const auto& [slotn, slot] : bvm.slots()) {
            const auto& vols = slot->volumes();
            for (size_t i = 0; i < vols.size(); i++) {
              const auto& v = vols[i];
              tbl.addRow(slotn, i, "", v.layers.size(),
                         v.extent_size * v.extents.size() / gb);
            }
          }
          tbl.print();
        }
      } else if (input == "new-slot" || input == "ns") {
        if (bvm.slots_used() >= bvm.slots_total()) {
          fmt::print("There are no more free slots.\n");
          continue;
        }

        std::string passphrase = prompt_passphrase();
        if (passphrase.empty()) {
          std::cerr << "Passphrase must not be empty" << std::endl;
          continue;
        }
        if (passphrase != prompt_passphrase("Verify passphrase: ")) {
          fmt::print("Passwords must match.\n");
          continue;
        }
        fmt::print("Creating slot... ");
        std::cout.flush();

        auto slot = bvm.createSlot(passphrase);
        fmt::print("done\n");
        fmt::print("Slot {} created\n", slot->slotn());
        dirtySlots[slot->slotn()] = true;
      } else if (input.starts_with("new-volume") || input.starts_with("nv")) {
        const std::regex nvreg(
            R"(^(?:new-volume|nv)\s+([0-7])\s+(\d+)\s*((?:.*?/\d+\s*))?$)");
        std::smatch matches;
        if (!std::regex_match(input, matches, nvreg)) {
          fmt::print("usage: new-volume <slot> <extents> [layers...]\n");
          fmt::print(
              "example: new-volume 5 20 aes-xts-plain64/512 "
              "twofish-xts-plain64/512\n");
          fmt::print(
              "  creates a volume on slot 5 with 20 extents with two layers "
              "with\n  key sizes of 512\n");
          continue;
        }

        for (size_t i = 0; i < matches.size(); i++) {
          log->debug("match[{}]: {}", i, matches[i].str());
        }

        const uint8_t slotn = std::stoi(matches[1].str());
        const size_t extents = std::stoull(matches[2].str());

        if (!bvm.slots().contains(slotn)) {
          fmt::print("Invalid slot number: {}\n", slotn);
          continue;
        } else if (extents > bvm.extents_free()) {
          fmt::print(
              "Not enough free extents ({}) to create a volume with {} "
              "extents\n",
              bvm.extents_free(), extents);
          continue;
        }

        std::vector<Layer> layers;
        const std::string layers_str = matches[3].str();
        if (!layers_str.empty()) {
          const std::regex layers_reg(R"(\s*(.*?)/(\d+)\s*)");
          auto re_begin = std::sregex_iterator(layers_str.begin(),
                                               layers_str.end(), layers_reg);
          auto re_end = std::sregex_iterator();
          log->debug("Found {} matches.", std::distance(re_begin, re_end));
          if (std::distance(re_begin, re_end) == 0) {
            log->debug("regex does not match string: '{}'", layers_str);
            fmt::print("Error parsing layers: '{}'\n", layers_str);
            continue;
          }
          for (std::sregex_iterator i = re_begin; i != re_end; ++i) {
            std::smatch match = *i;
            log->debug("matches size = {}", match.size());
            for (size_t j = 0; j < match.size(); j++) {
              log->debug("  match[{}] = {}", j, match[j]);
            }
            layers.emplace_back(match[1].str(), std::stoll(matches[2].str()));
          }
          fmt::print("layers size: {}\n", layers.size());
        }

        if (layers.size() == 0) {
          layers.emplace_back("aes-xts-essiv:sha256", 512);
        }
        bvm.addVolume(slotn, extents, layers);
        dirtySlots[slotn] = true;
        fmt::print("Volume created with {} extents and {} layers\n", extents,
                   layers.size());
      } else if (input.starts_with("remove-volume")) {
        const std::regex reg(R"(^(?:remove-volume)\s*([0-7])\s*(\d+)\s*$)");
        std::smatch matches;
        if (!std::regex_match(input, matches, reg)) {
          fmt::print("usage: remove-volume <slot> <volume number>\n");
          fmt::print("example: remove-volume 0 10\n");
          fmt::print("  removes volume 10 from slot 0\n");
          continue;
        }
        const uint8_t slotn = std::stoi(matches[1].str());
        const size_t voln = std::stoull(matches[2].str());
        if (!bvm.slots().contains(slotn)) {
          fmt::print("Invalid slot number: {}\n", slotn);
          continue;
        }

        auto slot = bvm.slots()[slotn];
        if (voln >= slot->volumes().size()) {
          fmt::print("Invalid volume number {} for slot {}\n", voln, slotn);
          continue;
        }
        bvm.removeVolume(slotn, voln);
        dirtySlots[slotn] = true;
        fmt::print("Volume {} on slot {} removed\n", voln, slotn);
      } else if (input == "unlock" || input == "u") {
        auto slot = bvm.unlockSlot(prompt_passphrase());
        if (slot != nullptr) {
          fmt::print("Slot {} unlocked.\n", slot->slotn());
        } else {
          fmt::print("Failed to unlock slot.\n");
        }
      } else if (input.starts_with("lock") || input.starts_with("l ")) {
        const std::regex lreg(R"(^(?:lock|l) ([0-7])\s*$)");
        std::smatch matches;
        if (!std::regex_match(input, matches, lreg)) {
          fmt::print("usage: lock <slot>\n");
          continue;
        }
        auto slotn = stoi(matches[1].str());
        if (!bvm.slots().contains(slotn)) {
          fmt::print("Slot {} is not unlocked nevertheless...\n", slotn);
        }
        bvm.closeSlot(slotn);
        fmt::print("Slot {} locked.\n", slotn);
      } else if (input == "save" || input == "write" || input == "w") {
        fmt::print("Saving\n");
        for (const auto& [slotn, dirty] : dirtySlots) {
          if (dirty) {
            fmt::print("saving slot {}\n", slotn);
            bvm.writeSlot(slotn);
            dirtySlots[slotn] = false;
          }
        }
        fmt::print("Done\n");
      } else if (input.starts_with("mknode")) {
        const std::regex reg(R"(^(?:mknode) ([0-7])\s*(\d+)\s*(\w+)\s*$)");
        std::smatch matches;
        if (!std::regex_match(input, matches, reg)) {
          fmt::print("usage: mknode <slot> <volume> <name>\n");
          fmt::print("example: mknode 0 2 test\n");
          fmt::print(
              "  Creates a node at /dev/mapper/test for volume 2 of slot 0\n");
          continue;
        }

        auto slotn = stoi(matches[1].str());
        if (!bvm.slots().contains(slotn)) {
          fmt::print("Slot {} is not unlocked\n", slotn);
        }

        const auto& slot = bvm.slots().at(slotn);
        auto voln = stoull(matches[2].str());
        if (voln >= slot->volumes().size()) {
          fmt::print("Invalid volume number {} for slot {}\n", voln, slotn);
        }

        const auto& vol = slot->volumes().at(voln);
        fmt::print("creating device mapper task\n");

        fmt::print("1. Creating linear device\n");
        dm_log_init_verbose(2);
        dm_task* dmt{nullptr};
        if (!(dmt = dm_task_create(DM_DEVICE_CREATE))) {
          fmt::print("Failed to create device mapper task\n");
          continue;
        }

        if (!dm_task_enable_checks(dmt)) {
          fmt::print("Failed to enable checks\n");
          dm_task_destroy(dmt);
          continue;
        }

        auto name = matches[3].str();
        std::string dev_name = fmt::format("bvm_linear_{}", name);
        if (!dm_task_set_name(dmt, dev_name.c_str())) {
          fmt::print("Failed to set dev name to {}\n", dev_name);
          dm_task_destroy(dmt);
          continue;
        }

        // create linear target
        // device mapper sector size, 512 bytes
        static constexpr size_t sector_size = 512;
        static_assert((BVM::EXTENT_SIZE % sector_size) == 0,
                      "EXTENT_SIZE must be divisible by sector size of 512");

        const auto& extents = vol.extents;
        auto sectors = vol.extent_size / sector_size;
        size_t start = 0;
        bool error = false;
        for (auto& extn : extents) {
          // offset within original file
          auto offset =
              bvm.bootstrap_size() + ((extn * vol.extent_size) / sector_size);

          // create table
          auto target_args = fmt::format(
              "{path} {offset}", "path"_a = fs::absolute(bvm.path()).string(),
              "offset"_a = offset);
          fmt::print("start = {}, sectors = {}\n", start, sectors);
          fmt::print("target args = {}\n", target_args);
          fmt::print("path = {path}, abs = {abs}\n", "path"_a = bvm.path(),
                     "abs"_a = fs::absolute(bvm.path()));
          if (!dm_task_add_target(dmt, start, sectors, "linear",
                                  target_args.c_str())) {
            error = true;
            fmt::print("Failed adding linear target\n");
            fmt::print("start={}, sectors={}, type=linear, args='{}'\n", start,
                       sectors, target_args);
            break;
          }
          start += sectors;
        }
        if (error) {
          fmt::print("Failed adding linear target\n");
          dm_task_destroy(dmt);
          continue;
        }

        uint32_t cookie = 0;
        uint16_t udev_flags = 0;
        if (!dm_task_set_cookie(dmt, &cookie, udev_flags)) {
          fmt::print("Failed on set cookie\n");
          continue;
        }
        if (!dm_task_run(dmt)) {
          fmt::print("Failed on task run\n");
          dm_task_destroy(dmt);
          continue;
        }

        dm_task_destroy(dmt);
        dmt = nullptr;
      } else if (input.starts_with("rmnode")) {
        const std::regex reg(R"(^(?:rmnode) (\w+)\s*$)");
        std::smatch matches;
        if (!std::regex_match(input, matches, reg)) {
          fmt::print("usage: rmnode <name>\n");
          fmt::print("example: rmnode test\n");
          fmt::print("  Removes node at /dev/mapper/test\n");
          continue;
        }

        auto name = matches[1].str();
        std::string dev_name = fmt::format("bvm_linear_{}", name);
        dm_task* dmt{nullptr};
        if (!(dmt = dm_task_create(DM_DEVICE_REMOVE))) {
          fmt::print("Failed on task create\n");
          continue;
        }
      }
    }
    std::cout << std::endl;
  });
}

namespace bvm {
void setup_cli(CLI::App& app) {
  auto log = spdlog::stderr_color_mt("bvm.cli");
  assert(log != nullptr);
  log->set_level(spdlog::level::debug);

  app.fallthrough();

  register_version_command(app);
  register_shell_command(app);
  app.require_subcommand(1);
}
}  // namespace bvm
