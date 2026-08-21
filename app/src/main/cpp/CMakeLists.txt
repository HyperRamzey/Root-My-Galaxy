cmake_minimum_required(VERSION 3.22.1)
project(s25u_native LANGUAGES C)

add_library(s25u_native SHARED native_probe.c)

# Maximum optimization for arm64-v8a
target_compile_options(s25u_native PRIVATE
    -O3
    -march=armv8-a+crc+crypto
    -mtune=cortex-a76
    -flto=thin
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
    -fomit-frame-pointer
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    -Wall -Wextra -Werror
)
target_link_options(s25u_native PRIVATE
    -flto=thin
    -Wl,--gc-sections
    -Wl,-O3
    -Wl,--icf=all
)
target_link_libraries(s25u_native PRIVATE log)
