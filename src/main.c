/* Copyright 2021 Kelvin Hammond <hammond.kelvin@gmail.com> */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char* argv[]) {
#if !defined(BVM_DESCRIPTION)
#error "BVM_DESCRIPTION must be defined"
#endif

  printf("Hello world\n");

  return 0;
}
