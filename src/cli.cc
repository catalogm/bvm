/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <fmt/format.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <atomic>
#include <cassert>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "bvm/bvm.hh"
#include "bvm/cli.hh"

#if !(defined(BVM_VERSION_MAJOR) && defined(BVM_VERSION_MINOR) && \
      defined(BVM_VERSION_PATCH))
#error "BVM_VERSION_* must be defined"
#endif

using namespace fmt::literals;
namespace fs = std::filesystem;
using bvm::BVM;

struct GlobalOptions {
  fs::path path;
};
using GlobalOptionsPtr = std::shared_ptr<GlobalOptions>;

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
}

inline void register_init_command(CLI::App& app) {
  CLI::App* sub = app.add_subcommand("init", "Initialize a repository");
  struct Options {
    std::string path = ".";
  };
  auto opts = std::make_shared<Options>();

  sub->add_option("directory", opts->path, "Repo directory", true);
  sub->callback([opts]() {
    auto log = spdlog::get("bvm.cli");
    log->debug("path = '{}'", opts->path);
    auto bvm = std::make_shared<BVM>(opts->path);
    log->debug("bvm = {}", bvm);
  });
}

namespace bvm {
void setup_cli(CLI::App& app) {
  auto log = spdlog::stderr_color_mt("bvm.cli");
  assert(log != nullptr);
  log->set_level(spdlog::level::debug);

  app.fallthrough();

  register_version_command(app);
  register_init_command(app);
  app.require_subcommand(1);
}
}  // namespace bvm
