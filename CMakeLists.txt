cmake_minimum_required(VERSION 3.9.2)

set(CMAKE_LEGACY_CYGWIN_WIN32 0)
cmake_policy(SET CMP0048 NEW)
set(CXX_STANDARD_REQUIRED 1)

include(GoogleTest)

project(bvm
    VERSION 0.0.1
    DESCRIPTION "Book volume manager"
    LANGUAGES CXX)

add_compile_definitions(
    BVM_DESCRIPTION="${PROJECT_DESCRIPTION}"
    BVM_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    BVM_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    BVM_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    BVM_VERSION_TWEAK=${PROJECT_VERSION_TWEAK}
)

find_package(PkgConfig REQUIRED)
enable_testing()

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    add_compile_options(/W4 /WX /EHsc)
else()
    add_compile_options(-Wall -Wextra -Werror -Wpedantic)
endif()

# include third_party/
add_subdirectory(third_party)

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
    "${PROJECT_SOURCE_DIR}/third_party/include"
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/third_party/CRoaring/cpp"
    "${PROJECT_SOURCE_DIR}/third_party/CRoaring/include"
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

MESSAGE( STATUS "CMAKE_SYSTEM_PROCESSOR: " ${CMAKE_SYSTEM_PROCESSOR})
MESSAGE( STATUS "CMAKE_BUILD_TYPE: " ${CMAKE_BUILD_TYPE} ) # this tends to be "sticky" so you can remain unknowingly in debug mode
MESSAGE( STATUS "CMAKE_CXX_COMPILER: " ${CMAKE_CXX_COMPILER} ) # important to know which compiler is used
MESSAGE( STATUS "CMAKE_CXX_FLAGS: " ${CMAKE_CXX_FLAGS} ) # important to know the flags
MESSAGE( STATUS "CMAKE_CXX_FLAGS_DEBUG: " ${CMAKE_CXX_FLAGS_DEBUG} )
MESSAGE( STATUS "CMAKE_CXX_FLAGS_RELEASE: " ${CMAKE_CXX_FLAGS_RELEASE} )
MESSAGE( STATUS "BVM_DESCRIPTION:   " ${PROJECT_DESCRIPTION} )
MESSAGE( STATUS "BVM_VERSION_MAJOR: " ${PROJECT_VERSION_MAJOR} )
MESSAGE( STATUS "BVM_VERSION_MINOR: " ${PROJECT_VERSION_MINOR} )
MESSAGE( STATUS "BVM_VERSION_PATCH: " ${PROJECT_VERSION_PATCH} )
MESSAGE( STATUS "BVM_VERSION_TWEAK: " ${PROJECT_VERSION_TWEAK} )

