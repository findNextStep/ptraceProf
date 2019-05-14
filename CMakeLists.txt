cmake_minimum_required(VERSION 3.0)
project(ptrace_prof)

include_directories(include)

include_directories(
    third_party/json/single_include
)

add_compile_options(-std=c++17)
add_compile_options(-g -Wall)
link_libraries(pthread)
link_libraries(sqlite3)
# SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
# SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -pg")
# SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pg")
# SET(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -pg")


add_library(typedef src/typedef.cpp)
add_library(processProf src/processTrace.cpp)

add_library(mapsReader src/mapsReader.cpp)
add_library(orderMap src/orderMap.cpp)
add_library(pipe src/pipe.cpp)
add_library(readDump src/readDump.cpp)

add_executable(main main.cpp)
target_link_libraries(main processProf mapsReader orderMap pipe readDump pthread typedef)

add_executable(map_read_test test/test_mapReader.cpp)
target_link_libraries(map_read_test mapsReader typedef)
add_executable(pipe_test test/test_pipe.cpp)
target_link_libraries(pipe_test pipe typedef)
add_executable(dumpReader_test test/test_readDump.cpp)
target_link_libraries(dumpReader_test readDump pipe typedef)
add_executable(file_exist_test test/test_file_exist.cpp)
target_link_libraries(file_exist_test orderMap mapsReader typedef)
