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

std::map<std::string, count_t> order_output_function(const result_t &ans) {
    std::map<std::string, count_t> result;
    for(auto [file, offset_to_times] : ans) {
        auto dumps = get_cmd_stream("objdump -d " + file);
        while(dumps) {
            auto [func_name, block] =
                dumpReader::read_block_with_func_name(dumps);
            if(func_name.size()) {
                for(auto [addre, _] : block) {
                    const auto times = offset_to_times[lltoString(addre)];
                    if(times) {
                        result[func_name] +=
                            offset_to_times[lltoString(addre)];
                    }
                }
            }
        }
    }
    return result;
}

} // ptraceProf
