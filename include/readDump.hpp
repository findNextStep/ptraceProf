#pragma once

#include "pipe.hpp"
#include "mapsReader.hpp"
#include <unordered_map>
#include <sstream>
#include <string>
#include <vector>

namespace ptraceProf {
namespace DumpReader {

auto get_order(std::stringstream &&ss) {
    short i;
    std::vector<unsigned short> result;
    result.reserve(8);
    while(ss >> std::hex >> i) {
        result.push_back(i);
    }
    return result;
}

struct order_map {
    int address;
    std::vector<unsigned short> order;
    std::string info;
};

auto deal_line_order(const std::string &line) {
    int i = -1;
    std::stringstream ss(line);
    ss >> std::hex >> i;
    if(ss.peek() == ':') {
        ss.get(); // skip ':'
        char a[24];
        ss.readsome(a, 23);
        std::vector<unsigned short>order(get_order(std::stringstream(a)));
        std::string resut;
        std::getline(ss, resut);
        return order_map{i, order, resut};
    }
    return order_map{-1};
}

auto try_read_header(const std::string &line) {
    char name[100];
    unsigned int addr = -1;
    if(sscanf(line.c_str(), "%x <%s>:", &addr, name) == 2) {
        return true;
    } else {
        return false;
    }
}

} // DumpReader
} // ptraceProf
