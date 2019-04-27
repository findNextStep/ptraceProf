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

namespace ptraceProf {

class pipstream: public std::ifstream {
    std::string pip_name;
public:
    pipstream(const std::string &pipName): pip_name(pipName), std::ifstream(pipName) { }
    virtual ~pipstream() {
        unlink(pip_name.c_str());
    }
};

auto get_cmd_stream(char *const *cmd) {
    const std::string pipe_name = "/tmp/ptrace" + std::to_string(rand());
    std::cout << mkfifo(pipe_name.c_str(), 0666) << '\n';
    int pid = fork();
    if(pid < 0) {
        std::cerr << "fork error" << std::endl;
        exit(1);
    }
    if(pid > 0) {
        return pipstream(pipe_name);
    } else {
        // fprintf(stdout,"file %s\n",pipe_name.c_str());
        if (freopen(pipe_name.c_str(), "w", stdout) == NULL){
            fprintf(stderr,"open pipe fail\n");
        }
        if(execv(cmd[0], cmd)){
            fprintf(stderr,"return is not 0\n");
        }
        fclose(stdout);
        unlink(pipe_name.c_str());
        exit(0);
    }
}
auto get_cmd_stream(std::vector<std::string> &&cmd) {
    std::vector<char *> mid;
    for(auto &m : cmd) {
        mid.push_back(m.data());
    }
    return get_cmd_stream(mid.data());
}
auto get_cmd_stream(const std::string &&cmd) {
    return get_cmd_stream({"/bin/sh", "-c", cmd});
}

}