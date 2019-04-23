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

using ptraceProf::mapsReader::mem_range;
using result_t = std::vector < std::tuple<std::string, mem_range, std::vector<unsigned long long> > >;

inline bool file_exist(const std::string &path) {
    // TODO change to c++17 filesystem if c++17 enabled
    return !path.empty() && path[0] == '/' // fast check
           && !access(path.c_str(), F_OK);
}

unsigned int get_address(
    const std::vector<mem_range> &range,
    const unsigned int addre) {
    for(const auto &r : range) {
        if(addre > r.offset && addre < r.end - r.start + r.offset) {
            return r.start + addre - r.offset;
        }
    }
    // this code should not run
    std::cerr << "addre not in range" << std::endl;
    exit(1);
    return 0;
}

bool has_maped(const std::pair<std::string, std::vector<mem_range> > &file,
               const result_t &count) {
    if (!file_exist(file.first)){
        return true;
    }
    for(const auto &c : count) {
        if(std::get<0>(c) == file.first) {
            return true;
        }
    }
    return false;
}

bool no_repeat_map(const std::pair<std::string, std::vector<mem_range> > &file,
                   result_t &count) {
    if(!has_maped(file, count)) {
        for(const auto &range : file.second) {
            count.push_back(std::make_tuple(
                                file.first,
                                range,
                                std::vector<unsigned long long>(range.end - range.start, 0)));
        }
    }
}

void getProcessCount(const int pid,
                     result_t &count) {
    using ptraceProf::mapsReader::readMaps;
    using ptraceProf::mapsReader::mem_range;
    auto address_map = readMaps(pid);
    for(const auto &add_map : address_map) {
        no_repeat_map(add_map, count);
    }
}

auto getProcessCount(const int pid) {
    result_t count;
    getProcessCount(pid, count);
    return count;
}

} // namespace orderMap
} // namespace ptraceProf
