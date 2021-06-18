cmake_minimum_required(VERSION 3.14 FATAL_ERROR)

set(CMAKE_LEGACY_CYGWIN_WIN32 0)
cmake_policy(SET CMP0048 NEW)
set(CXX_STANDARD_REQUIRED 1)

project(bvm
    VERSION 0.0.1
    DESCRIPTION "Book Volume Manager"
    LANGUAGES C)

add_compile_definitions(
    BVM_DESCRIPTION="${PROJECT_DESCRIPTION}"
    BVM_VERSION_MAJOR=${PROJECT_VERSION_MAJOR}
    BVM_VERSION_MINOR=${PROJECT_VERSION_MINOR}
    BVM_VERSION_PATCH=${PROJECT_VERSION_PATCH}
    BVM_VERSION_TWEAK=${PROJECT_VERSION_TWEAK}
    LOG_USE_COLOR=true
)

find_package(PkgConfig REQUIRED)

# third party
#add_subdirectory(third_party)

# add the binary tree to the search path for include files
include_directories(
    #"${PROJECT_SOURCE_DIR}/third_party/include"
    "${PROJECT_SOURCE_DIR}/include"
    "${PROJECT_SOURCE_DIR}/third_party/log.c/src"
)

pkg_check_modules(BVM REQUIRED libcbor libgcrypt libargon2)
pkg_check_modules(BVM_TEST REQUIRED cmocka)

if ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    #add_compile_options(/W4 /WX /EHsc)
    set(BVM_CFLAGS ${BVM_CFLAGS} /W4 /WX /EHsc)
else()
    #add_compile_options(-Wall -Wextra -Werror -Wpedantic)
    set(BVM_CFLAGS 
        ${BVM_CFLAGS} 
        -Wall -Wextra -Werror -Wpedantic -Wunreachable-code -ftrapv -fsanitize=undefined -fsanitize=leak
        -ffile-prefix-map=${PROJECT_SOURCE_DIR}=.)
    set(BVM_TEST_CFLAGS ${BVM_TEST_CFLAGS} ${BVM_CFLAGS})
endif()

set(BVM_LIBRARIES
    ${BVM_LIBRARIES}
    dw dl pthread
    ubsan  # used by -fsanitize=undefined CFLAG
)
set(SOURCE_FILES
    third_party/log.c/src/log.c
    src/bvm.c
    src/bvm_key.c
    src/bvm_chapter.c
    src/bvm_dev_mem.c
    src/bvm_bitmap.c)
set(TEST_FILES tests/main.c)

# TODO: make a library target for libbvm
add_library(bvm SHARED ${SOURCE_FILES})
set_target_properties(bvm PROPERTIES CMAKE_C_STANDARD 99)
target_link_libraries(bvm ${BVM_LIBRARIES})
target_include_directories(bvm PUBLIC ${BVM_INCLUDE_DIRS})
target_compile_options(bvm PUBLIC ${BVM_CFLAGS} ${BVM_CFLAGS_OTHER})

# Binary
#add_executable(bvm-bin ${SOURCE_FILES} src/main.c)
#set_target_properties(bvm-bin PROPERTIES OUTPUT_NAME bvm)
#set_target_properties(bvm-bin PROPERTIES CMAKE_C_STANDARD 99)
#target_link_libraries(bvm-bin ${BVM_LIBRARIES})
#target_include_directories(bvm-bin PUBLIC ${BVM_INCLUDE_DIRS})
#target_compile_options(bvm-bin PUBLIC ${BVM_CFLAGS_OTHER})

# Tests
enable_testing()
add_executable(test_bvm ${TEST_FILES})
set_target_properties(test_bvm PROPERTIES CMAKE_C_STANDARD 99)
target_link_libraries(test_bvm bvm ${BVM_LIBRARIES} ${BVM_TEST_LIBRARIES})
target_include_directories(test_bvm PUBLIC ${BVM_INCLUDE_DIRS} ${BVM_TEST_INCLUDE_DIRS})
target_compile_options(test_bvm PUBLIC ${BVM_CFLAGS_OTHER} ${BVM_TEST_CFLAGS} ${BVM_TEST_CFLAGS_OTHER})
add_test(NAME test_bvm COMMAND test_bvm) 

MESSAGE( STATUS "CMAKE_SYSTEM_PROCESSOR: " ${CMAKE_SYSTEM_PROCESSOR})
MESSAGE( STATUS "CMAKE_BUILD_TYPE: " ${CMAKE_BUILD_TYPE} ) # this tends to be "sticky" so you can remain unknowingly in debug mode
MESSAGE( STATUS "CMAKE_C_COMPILER: " ${CMAKE_C_COMPILER} ) # important to know which compiler is used
MESSAGE( STATUS "CMAKE_C_FLAGS: " ${CMAKE_C_FLAGS} ) # important to know the flags
MESSAGE( STATUS "CMAKE_C_FLAGS_DEBUG: " ${CMAKE_C_FLAGS_DEBUG} )
MESSAGE( STATUS "CMAKE_C_FLAGS_RELEASE: " ${CMAKE_C_FLAGS_RELEASE} )
MESSAGE( STATUS "BVM_DESCRIPTION:   " ${PROJECT_DESCRIPTION} )
MESSAGE( STATUS "BVM_VERSION_MAJOR: " ${PROJECT_VERSION_MAJOR} )
MESSAGE( STATUS "BVM_VERSION_MINOR: " ${PROJECT_VERSION_MINOR} )
MESSAGE( STATUS "BVM_VERSION_PATCH: " ${PROJECT_VERSION_PATCH} )
MESSAGE( STATUS "BVM_VERSION_TWEAK: " ${PROJECT_VERSION_TWEAK} )

