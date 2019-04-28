#pragma once
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <math.h>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>

namespace ptraceProf {

class pipstream: public std::ifstream {
    std::string pip_name;
public:
    pipstream(const std::string &pipName): pip_name(pipName), std::ifstream(pipName) { }
    virtual ~pipstream() {
        unlink(pip_name.c_str());
    }
};
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


auto get_cmd_stream(const std::string &&cmd,bool pip = true) {
    return exec(cmd.c_str());
}

}