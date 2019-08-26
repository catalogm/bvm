

# Roaring bitmap
set(ROARING_BUILD_STATIC ON CACHE BOOL "croaring: build static library" FORCE)
set(ENABLE_ROARING_TESTS OFF)
add_subdirectory(CRoaring EXCLUDE_FROM_ALL)

