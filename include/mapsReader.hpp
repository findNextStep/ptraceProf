#pragma once

#include <typedef.hpp>
#include <string>
#include <vector>
#include <map>

namespace ptraceProf {
namespace mapsReader {
struct mem_range {
    ip_t start;
    ip_t end;
    ip_t offset;
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

