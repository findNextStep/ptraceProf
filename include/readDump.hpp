#pragma once

#include "pipe.hpp"
#include <unordered_map>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <istream>

namespace ptraceProf {
namespace dumpReader {

using pipstream = std::stringstream;
using result_t = std::map< unsigned int, std::tuple < std::vector<unsigned short>, std::string > >;

std::vector<unsigned short>get_order(std::istream &&ss);

struct order_map {
    int address;
    std::vector<unsigned short> order;
    std::string info;
};

order_map deal_line_order(const std::string &line);

std::string try_read_header(const std::string &line);

result_t read_block(pipstream &is);

result_t read_objdump(pipstream &is);
result_t read_objdump(pipstream &&is);

} // DumpReader
} // ptraceProf
