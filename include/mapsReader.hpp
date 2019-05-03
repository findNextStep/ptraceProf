#pragma once

#include <string>
#include <fstream>
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

using result_t = std::map<std::string, std::vector<mem_range> >;

result_t readMaps(std::istream &&fs);
result_t readMaps(int pid);
result_t readMaps();


} // mapsReader
} // ptraceProf

