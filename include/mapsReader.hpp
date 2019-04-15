#pragma once

#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <map>

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
inline static mem_map get_mem_map_from_line(const std::string &line) {
    unsigned long long start, end, offset;
    char file_name[255] = "\0";
    sscanf(line.c_str(), "%llx-%llx %*s %llx %*d:%*d %*d %s", &start, &end, &offset, file_name);
    return {{start, end, offset}, std::string(file_name)};
}

auto readMaps(std::ifstream &&fs) {
    std::vector<mem_map> result;
    while(!fs.eof()) {
        std::string line;
        std::getline(fs, line);
        result.push_back(get_mem_map_from_line(line));
    }
    return result;
}

inline auto readMaps(int pid) {
    return readMaps(std::ifstream(get_file_name_from_pid(pid)));
}

} // mapsReader
} // ptraceProf

