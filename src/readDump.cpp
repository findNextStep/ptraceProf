#include "readDump.hpp"


namespace ptraceProf {
namespace dumpReader {

 order_t get_order(std::istream &&ss) {
    short i;
    order_t result;
    result.reserve(8);
    while(ss >> std::hex >> i) {
        result.push_back(i);
    }
    return result;
}


order_map deal_line_order(const std::string &line) {
    int i = -1;
    std::stringstream ss(line);
    ss >> std::hex >> i;
    if(ss.peek() == ':') {
        ss.get(); // skip ':'
        char a[24];
        ss.readsome(a, 23);
        order_t order(get_order(std::stringstream(a)));
        std::string resut;
        std::getline(ss, resut);
        return order_map{i, order, resut};
    }
    return order_map{-1};
}

std::string try_read_header(const std::string &line) {
    char name[1000];
    unsigned int addr = -1;
    if(sscanf(line.c_str(), "%x <%s>:", &addr, name) == 2) {
        return std::string(name);
    } else {
        return std::string("");
    }
}

result_t read_block(pipstream &is) {
    std::string line;
    std::getline(is, line);
    std::string func_name = try_read_header(line);
    result_t result;
    while(func_name.size()) {
        std::string line;
        if(!std::getline(is, line)){
            break;
        }
        auto order = deal_line_order(line);
        if(order.address == -1) {
            break;
        }
        result[order.address] = std::make_tuple(order.order, order.info);
    }
    return result;
}

result_t read_objdump(pipstream &is) {
    result_t result;
    while(is) {
        auto block = read_block(is);
        for(const auto &item : block) {
            result.emplace(item);
        }
    }
    return result;
}
result_t read_objdump(pipstream &&is) {
    return read_objdump(is);
}

} // DumpReader
} // ptraceProf