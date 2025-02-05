cmake_minimum_required(VERSION 3.15)
project(BinaryLense 
            VERSION 0.1
            DESCRIPTION "A Terrible Binary Analysis Program"
            LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

add_executable(BinaryLense
    include/loader.hpp
    src/main.cpp)

find_library(LIBRARY_BFD bfd)

if (LIBRARY_BFD)
    target_link_libraries(BinaryLense PRIVATE ${LIBRARY_BFD})
else()
    message([FATAL_ERROR] "Library BFD not found. This is a low-spec binary analyzer, dummy.")
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Windows")
    target_compile_options(BinaryLense PRIVATE /W4)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Linux")
    target_compile_options(BinaryLense PRIVATE -Wall -Wextra -Wpedantic)
elseif (CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    # other macOS-specific flags for Clang
endif()


