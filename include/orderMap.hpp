#pragma once
#include "mapsReader.hpp"
#include "readDump.hpp"
#include "pipe.hpp"

#include <fcntl.h>  // F_OK
#include <unistd.h> // access
#include <string>
#include <fstream>

namespace ptraceProf {
namespace orderMap {

inline bool file_exist(const std::string &path) {
    // TODO change to c++17 filesystem if c++17 enabled
    return !path.empty() && path[0] == '/' // fast check
           && !access(path.c_str(), F_OK);
}

unsigned int get_address(
    const std::vector<ptraceProf::mapsReader::mem_range> &range,
    const unsigned int addre) {
    for(auto r : range) {
        if(addre > r.offset && addre < r.end - r.start + r.offset) {
            return r.start + addre - r.offset;
        }
    }
    // this code should not run
    std::cerr << "addre not in range" << std::endl;
    exit(1);
    return 0;
}

auto getProcessMap(const int pid) {
    using ptraceProf::mapsReader::readMaps;
    using ptraceProf::mapsReader::mem_range;
    using ptraceProf::dumpReader::read_objdump;
    auto address_map = readMaps(pid);
    std::unordered_map <unsigned int, std::tuple< std::vector<unsigned short>, std::string > > result;
    for(const std::pair<std::string, std::vector<mem_range> > &add_map : address_map) {
        if(file_exist(add_map.first)) {
            std::unordered_map < unsigned int, std::tuple <
            std::vector<unsigned short>,
                std::string > > dump =
                    read_objdump(get_cmd_stream({"/usr/bin/objdump", "-d", add_map.first}));
            for(auto dump_item : dump) {
                result[get_address(add_map.second, dump_item.first)] = dump_item.second;
            }
        }
    }
    return result;
}

auto getProcessCount(const int pid) {
    using ptraceProf::mapsReader::readMaps;
    using ptraceProf::mapsReader::mem_range;
    auto address_map = readMaps(pid);
    std::vector < std::tuple<std::string, mem_range, std::vector<unsigned long long> > > count;
    for(const std::pair<std::string, std::vector<mem_range> > &add_map : address_map) {
        if(file_exist(add_map.first)) {
            for(auto range : add_map.second) {
                count.push_back(std::make_tuple(
                                    add_map.first,
                                    range,
                                    std::vector<unsigned long long>(range.end - range.start, 0)));
            }
        }
    }
    return count;
}

} // namespace orderMap
} // namespace ptraceProf
