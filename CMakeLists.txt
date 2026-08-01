cmake_minimum_required(VERSION 3.20)
project(mavlink_crypto_test C)

set(CMAKE_C_STANDARD 99)

# Tell the compiler where the current directory is so header includes resolve cleanly
include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# Set up the main runnable execution target
add_executable(mavlink_test main.c)