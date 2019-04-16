#pragma once

#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>
#include <set>

namespace ptraceProf {
namespace mapsReader {
struct mem_range {
    unsigned long long start;
    unsigned long long end;
    unsigned long long offset;
};

struct mem_map {
    /* identify the memery range */
    mem_range range;
    std::string file_name;
};

inline static std::string get_file_name_from_pid(int pid) {
    char file_name[255];
    sprintf(file_name, "/proc/%d/maps", pid);
    return std::string(file_name);
}

inline constexpr auto get_file_name_from_pid() {
    return "/proc/self/maps";
}

inline static auto get_mem_map_from_line(const std::string &line) {
    unsigned long long start, end, offset;
    char file_name[255] = "\0";
    sscanf(line.c_str(), "%llx-%llx %*s %llx %*d:%*d %*d %s", &start, &end, &offset, file_name);
    return std::make_pair(mem_range{start, end, offset}, std::string(file_name));
}

auto readMaps(std::ifstream &&fs) {
    std::map<std::string, std::vector<mem_range>> result;
    while(!fs.eof()) {
        std::string line;
        std::getline(fs, line);
        auto [map, file] = get_mem_map_from_line(line);
        if(file.size()) {
            result[file].push_back(map);
        }
    }
    return result;
}

inline auto readMaps(int pid) {
    return readMaps(std::ifstream(get_file_name_from_pid(pid)));
}
inline auto readMaps() {
    return readMaps(std::ifstream(get_file_name_from_pid()));
}


} // mapsReader
} // ptraceProf

