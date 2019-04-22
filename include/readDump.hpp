#pragma once

#include "pipe.hpp"
#include <unordered_map>
#include <sstream>
#include <string>
#include <vector>
#include <istream>

namespace ptraceProf {
namespace dumpReader {

auto get_order(std::istream &&ss) {
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
        return std::string(name);
    } else {
        return std::string("");
    }
}

auto read_block(std::istream &is) {
    std::string line;
    std::getline(is, line);
    std::string func_name = try_read_header(line);
    std::unordered_map < unsigned int, std::tuple <
    std::vector<unsigned short>,
        std::string > > result;
    while(func_name.size()) {
        std::string line;
        std::getline(is, line);
        auto order = deal_line_order(line);
        if(order.address == -1) {
            break;
        }
        result[order.address] = std::make_tuple(order.order, order.info);
    }
    return result;
}

auto read_objdump(std::istream &is) {
    std::unordered_map < unsigned int, std::tuple <
    std::vector<unsigned short>,
        std::string > > result;
    while(!is.eof()) {
        auto block = read_block(is);
        for(const auto &item : block) {
            result.emplace(item);
        }
    }
    return result;
}
auto read_objdump(std::istream &&is) {
    std::unordered_map < unsigned int, std::tuple <
    std::vector<unsigned short>,
        std::string > > result;
    while(!is.eof()) {
        auto block = read_block(is);
        for(const auto &item : block) {
            result.emplace(item);
        }
    }
    return result;
}

} // DumpReader
} // ptraceProf
