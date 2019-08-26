cmake_minimum_required(VERSION 3.9.2)

set(CMAKE_LEGACY_CYGWIN_WIN32 0)
cmake_policy(SET CMP0048 NEW)
set(CXX_STANDARD_REQUIRED 1)

include(GoogleTest)

project(bvm
    VERSION 0.0.1
    LANGUAGES CXX)

find_package(PkgConfig REQUIRED)
enable_testing()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU" OR
    "${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    set(warnings "-Wall -Wextra -Werror -Wpedantic")
elseif ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    set(warnings "/W4 /WX /EHsc")
endif()

if (NOT CONFIGURED_ONCE)
    set(CMAKE_CXX_FLAGS "${warnings}"
        CACHE STRING "Flags used by the compiler during all build types." FORCE)
    set(CMAKE_C_FLAGS   "${warnings}"
        CACHE STRING "Flags used by the compiler during all build types." FORCE)
endif()

# include lib/
add_subdirectory(lib)

# boost
add_compile_definitions(BOOST_DLL_USE_STD_FS=true)

# fmtlib
add_compile_definitions(FMT_STRING_ALIAS=1)

# backward stacktracing
#add_compile_definitions(BACKWARD_HAS_BFD=1)
#add_compile_definitions(BACKWARD_HAS_DWARF=1)
add_compile_definitions(BACKWARD_HAS_DW=1)

# add the binary tree to the search path for include files
include_directories(
    "${PROJECT_SOURCE_DIR}/lib/include"
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/lib/CRoaring/cpp"
    "${PROJECT_SOURCE_DIR}/lib/CRoaring/include"
)

pkg_check_modules(BVM REQUIRED devmapper spdlog fmt botan-2)

set(BVM_LIBRARIES ${BVM_LIBRARIES} stdc++fs dw dl pthread roaring)
set(SOURCE_FILES src/bvm.cc src/cli.cc)
set(TEST_FILES 
    tests/main.cc 
    tests/test_bvm_disk_sizes.cc
    tests/test_bvm_slot.cc
    tests/test_bvm_slot_create.cc 
    tests/test_bvm_wipe.cc)

# Tests
add_executable(test_bvm ${SOURCE_FILES} ${TEST_FILES})
set_property(TARGET test_bvm PROPERTY CXX_STANDARD 17)
target_link_libraries(test_bvm gtest ${BVM_LIBRARIES})
target_include_directories(test_bvm PUBLIC ${BVM_INCLUDE_DIRS})
target_compile_options(test_bvm PUBLIC ${BVM_CFLAGS_OTHER})
gtest_discover_tests(test_bvm)

# Binary
add_executable(bvm ${SOURCE_FILES} src/main.cc)
set_property(TARGET bvm PROPERTY CXX_STANDARD 17)
target_link_libraries(bvm ${BVM_LIBRARIES})
target_include_directories(bvm PUBLIC ${BVM_INCLUDE_DIRS})
target_compile_options(bvm PUBLIC ${BVM_CFLAGS_OTHER})

