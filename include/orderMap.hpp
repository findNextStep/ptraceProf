#pragma once
#include "mapsReader.hpp"

#include <fcntl.h>  // F_OK
#include <unistd.h> // access
#include <string>
#include <fstream>
#include <map>

namespace ptraceProf {
namespace orderMap {

using ptraceProf::mapsReader::mem_range;
using result_t = std::vector < std::tuple<std::string, mem_range, std::vector<std::map<ip_t ,unsigned int> > > >;

bool file_exist(const std::string &path);

unsigned int get_address(const std::vector<mem_range> &range, const unsigned int addre);

bool has_maped(const std::pair<std::string, std::vector<mem_range> > &file, const result_t &count);

bool no_repeat_map(const std::pair<std::string, std::vector<mem_range> > &file, result_t &count); 
void getProcessCount(const int pid, const ::ptraceProf::mapsReader::result_t&address_map, result_t &count); 
void getProcessCount(const int pid, result_t &count); 
result_t getProcessCount(const int pid);

} // namespace orderMap
} // namespace ptraceProf
