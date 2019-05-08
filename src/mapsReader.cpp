#include "mapsReader.hpp"

namespace ptraceProf {
namespace mapsReader {

inline static std::string get_file_name_from_pid(int pid) {
    char file_name[255];
    sprintf(file_name, "/proc/%d/maps", pid);
    return std::string(file_name);
}

inline std::string get_file_name_from_pid() {
    return "/proc/self/maps";
}

inline static auto get_mem_map_from_line(const std::string &line) {
    unsigned long long start, end, offset;
    char file_name[255] = "\0";
    int put = sscanf(line.c_str(), "%llx-%llx %*s %llx %*d:%*d %*d %s", &start, &end, &offset, file_name);
    if(put > 2) {
        return std::make_pair(mem_range{start, end, offset}, std::string(file_name));
    } else {
        return std::make_pair(mem_range{0, 0, 0}, std::string(file_name));
    }
}

result_t readMaps(std::istream &&fs) {
    result_t result;
    while(fs) {
        std::string line;
        std::getline(fs, line);
        auto [map, file] = get_mem_map_from_line(line);
        if(map.start != 0) {
            result[file].push_back(map);
        }
    }
    return result;
}

result_t readMaps(int pid) {
    return readMaps(std::ifstream(get_file_name_from_pid(pid)));
}

result_t readMaps() {
    return readMaps(std::ifstream(get_file_name_from_pid()));
}


} // mapsReader
} // ptraceProf