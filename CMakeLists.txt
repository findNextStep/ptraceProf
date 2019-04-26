cmake_minimum_required(VERSION 3.0)
project(ptrace_prof)

include_directories(include)

include_directories(third_party/json/single_include)

add_compile_options(-std=c++1z)
add_compile_options(-g)

add_executable(main main.cpp)

add_executable(map_read_test test/test_mapReader.cpp)
add_executable(pipe_test test/test_pipe.cpp)
add_executable(dumpReader_test test/test_readDump.cpp)
