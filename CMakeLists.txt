project(ptrace_prof)

include_directories(include)

add_compile_options(-std=c++14)

add_executable(main main.cpp)

add_executable(map_read_test test/test_mapReader.cpp)
