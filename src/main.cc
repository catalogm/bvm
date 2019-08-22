/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */
#include <execinfo.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>
#include <iostream>
#include <string>

#include "CLI11.hpp"
#include "backward.hpp"
#include "bvm/cli.hh"

void signal_handler(int sig) {
  const size_t asize{100};
  void *array[asize];
  size_t size;

  // get void*'s for all entries on the stack
  size = backtrace(array, asize);
  spdlog::error("Error: signal {}", sig);
  char **strings = backtrace_symbols(array, size);
  if (strings == NULL) {
    spdlog::critical("backtrace_symbols", std::strerror(errno));
    std::_Exit(EXIT_FAILURE);
  }

  for (size_t i = 0; i < asize; i++) {
    spdlog::critical("{}", strings[i]);
  }
  free(strings);
  std::_Exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {
  backward::SignalHandling sh;

  CLI::App app{"Book of Shadows: Volume Manager"};
  bvm::setup_cli(app);
  app.require_subcommand(1);

  auto console = spdlog::stderr_color_mt("console");
  console->set_level(spdlog::level::debug);

  CLI11_PARSE(app, argc, argv);

  return 0;
}
