#pragma once
#include "processTrace.hpp"
#include "readDump.hpp"
#include "pipe.hpp"
#include <map>

namespace ptraceProf {

std::string order_to_string(const order_t &order) {
    std::stringstream ss;
    ss << std::hex;
    for(auto i : order) {
        ss << i;
    }
    return ss.str();
}

std::map<std::string, count_t> order_output(const result_t &ans) {
    std::map<std::string, count_t> result;
    for(auto [file, offset_to_times] : ans) {
        auto dump = dumpReader::read_objdump(get_cmd_stream("objdump -d " + file));
        for(auto [offset, _] : dump) {
            auto [order, info] = _;
            const auto times = offset_to_times[lltoString(offset)];
            if(times) {
                result[order_to_string(order)] +=
                    offset_to_times[lltoString(offset)];
            }
        }
    }
    return result;
}

std::map<std::string, count_t> order_output_function(const result_t &ans, const std::string &file) {
    std::map<std::string, count_t> result;
    const auto &offset_to_times = ans.at(file);
    auto dumps = get_cmd_stream("objdump -d -C " + file);
    while(dumps) {
        auto [func_name, block] =
            dumpReader::read_block_with_func_name(dumps);
        if(func_name.size()) {
            for(auto [addre, _] : block) {
                const auto it = offset_to_times.find(lltoString(addre));
                if(it != offset_to_times.end()) {
                    result[func_name] += it->second;
                }
            }
        }
    }
    return result;
}

std::map<std::string, count_t> order_output_function(const result_t &ans) {
    std::map<std::string, count_t> result;
    for(auto [file, _] : ans) {
        result.merge(order_output_function(ans, file));
    }
    return result;
}

} // ptraceProf
