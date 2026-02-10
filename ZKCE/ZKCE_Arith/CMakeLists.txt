cmake_minimum_required(VERSION 3.15)
project(HEAAN)

set(CMAKE_CXX_STANDARD 14)

include_directories(lib)
include_directories(run)
include_directories(src)
include_directories(NTL)

file(GLOB SRC_FILES "src/*.cpp")

#add_executable(HEAAN run/runMPCmult.cpp ${SRC_FILES})
add_library(zkce_arith STATIC ${SRC_FILES})

target_link_libraries(zkce_arith gmp)
