#include "pipe.hpp"

namespace ptraceProf {

auto exec(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return std::stringstream(result);
}


std::stringstream get_cmd_stream(const std::string &&cmd) {
    return exec(cmd.c_str());
}


}