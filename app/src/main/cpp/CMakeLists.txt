cmake_minimum_required(VERSION 3.22.1)
project(s25u_native LANGUAGES C)

add_library(s25u_native SHARED native_probe.c)

# Maximum optimization for arm64-v8a (SM-F946B, Snapdragon 8 Gen 2)
target_compile_options(s25u_native PRIVATE
    -O3
    -march=armv8-a+crc+crypto
    -mtune=cortex-x3
    -flto=thin
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
    -fomit-frame-pointer
    -fno-unwind-tables
    -fno-asynchronous-unwind-tables
    # Override NDK toolchain defaults that cost perf/size
    -fno-stack-protector
    -U_FORTIFY_SOURCE
    -Wall -Wextra -Werror
)
# Strip debug info from the final .so
add_custom_command(TARGET s25u_native POST_BUILD
    COMMAND ${CMAKE_STRIP} $<TARGET_FILE:s25u_native>
)
target_link_options(s25u_native PRIVATE
    -flto=thin
    -Wl,--gc-sections
    -Wl,-O3
    -Wl,--icf=all
)
target_link_libraries(s25u_native PRIVATE log)
