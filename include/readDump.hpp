#pragma once

#include "typedef.hpp"
#include "pipe.hpp"
#include <unordered_map>
#include <map>
#include <sstream>
#include <string>
#include <vector>
#include <istream>
#include <set>

namespace ptraceProf {

using order_t = std::string;//std::vector<unsigned short>;

namespace dumpReader {

using pipstream = std::stringstream;
using result_t = std::map< ip_t, std::tuple < order_t, std::string > >;

order_t get_order(std::istream &&ss);

struct order_map {
    ip_t address;
    order_t order;
    std::string info;
};

order_map deal_line_order(const std::string &line);

std::string try_read_header(const std::string &line);

result_t read_block(pipstream &is);

std::pair<std::string,result_t> read_block_with_func_name(pipstream &is);

result_t read_objdump(pipstream &is);
result_t read_objdump(pipstream &&is);

std::pair<std::set<ip_t>,std::set<ip_t> >get_single_step_list(const std::string &file);

} // DumpReader
} // ptraceProf
