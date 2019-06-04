#include "pipe.hpp"
#include <stdio.h>
#include <unistd.h>
#include <array>
#include <memory>

namespace ptraceProf {

auto exec(const char *cmd) {
    std::array<char, 1024> buffer;
    std::string result;
    auto pipe = popen(cmd, "r");
    if(!pipe) {
        pclose(pipe);
        throw std::runtime_error("popen() failed!");
    }
    while(fgets(buffer.data(), buffer.size(), pipe) != nullptr) {
        result += buffer.data();
    }
    pclose(pipe);
    return std::stringstream(result);
}


std::stringstream get_cmd_stream(const std::string &&cmd) {
    return exec((cmd + " 2> /dev/null").c_str());
}


}