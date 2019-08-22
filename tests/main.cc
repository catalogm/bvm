/* Copyright 2019 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <execinfo.h>
#include <gtest/gtest.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>
#include <unistd.h>
#include <cerrno>
#include <csignal>

#include "backward.hpp"

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
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
