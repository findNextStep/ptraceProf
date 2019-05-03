cmake_minimum_required(VERSION 3.0)
project(ptrace_prof)

include_directories(include)

include_directories(
    third_party/json/single_include
    third_party/gethin/single_include
)

add_compile_options(-std=c++17)
add_compile_options(-g)

add_library(processProf src/processTrace.cpp)

add_library(mapsReader src/mapsReader.cpp)
add_library(orderMap src/orderMap.cpp)
add_library(pipe src/pipe.cpp)
add_library(readDump src/readDump.cpp)

add_executable(main main.cpp)
target_link_libraries(main processProf mapsReader orderMap pipe readDump pthread)

add_executable(map_read_test test/test_mapReader.cpp)
target_link_libraries(map_read_test mapsReader)
add_executable(pipe_test test/test_pipe.cpp)
target_link_libraries(pipe_test pipe)
add_executable(dumpReader_test test/test_readDump.cpp)
target_link_libraries(dumpReader_test readDump pipe)
