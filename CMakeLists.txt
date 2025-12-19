cmake_minimum_required(VERSION 3.16)

project(ad_crypt
    VERSION 1.0
    LANGUAGES C CXX
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

add_library(ad_crypt SHARED
    src/ad_crypt.c
)

# ---- INCLUDE DIRS ----
target_include_directories(ad_crypt
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt/inih/include
)

# ---- PREBUILT LIBSODIUM (IMPORTED TARGET) ----
add_library(libsodium SHARED IMPORTED)

set_target_properties(libsodium PROPERTIES
    IMPORTED_LOCATION
        ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt/libsodium/lib/libsodium.so
    INTERFACE_INCLUDE_DIRECTORIES
        ${CMAKE_CURRENT_SOURCE_DIR}/../../prebuilt/libsodium/include
)

# ---- LINK LIBRARIES ----
target_link_libraries(ad_crypt
    PUBLIC ad_logger
    PUBLIC libsodium
)

enable_testing()
add_subdirectory(tests)
