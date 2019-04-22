#include <iostream>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <stdio.h>
#include <chrono>
#include <thread>
#include <vector>
#include <dirent.h> // opendir
#include <sstream>

#include "orderMap.hpp"

bool process_pause(const int pid) {
    if(ptrace(PTRACE_ATTACH, pid, 0, 0)) {
        fprintf(stderr, "fail to attach pid :%d\n", pid);
        return false;
    }
    int status;
    if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
        fprintf(stderr, "fail to wait pid :%d\n", pid);
        return false;
    }
    return true;
}

void procsss_start(const int pid) {
    if(ptrace(PTRACE_DETACH, pid, 0, 0)) {
        fprintf(stderr, "fail to detach pid :%d\n", pid);
    }
}

static std::vector<pid_t> ListThreads(pid_t pid) {
    std::vector<pid_t> result;
    std::stringstream dirname;
    dirname << "/proc/" << pid << "/task";
    auto *dir = opendir(dirname.str().c_str());
    if(dir == nullptr) {
        // fail
        return {};
    }
    dirent *entry;
    while((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if(name[0] != '.') {
            result.push_back(static_cast<pid_t>(std::stoi(name)));
        }
    }
    return result;
}

void some_time_trace(const int pid) {
    int status;
    long orig_eax;
    while(1) {
        if(!process_pause(pid)) {
            return;
        }
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        wait(&status);
        if(WIFEXITED(status)) { //子进程发送退出信号，退出循环
            break;
        }
        long ip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
        procsss_start(pid);
        fprintf(stdout, "ip = %ld \n", ip);
    }
}

void dump_and_trace(const int pid) {
    int status = -1;
    wait(&status);
    if(WIFEXITED(status)) { //子进程发送退出信号，退出循环
        return;
    }
    std::cout << "start dump " << std::endl;
    auto m = ptraceProf::orderMap::getProcessCount(pid);
    std::cout << "end dump " << std::endl;
    auto range_cache = &m[0];
    while(1) {
        ptrace(PTRACE_SINGLEBLOCK, pid, 0, 0);
        // wait(&status);
        if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
            fprintf(stderr, "fail to wait pid :%d\n", pid);
            break;
        }
        long ip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
        bool in = false;
        if(ip >= std::get<1>(*range_cache).start && ip <= std::get<1>(*range_cache).end) {
            in = true;
            std::get<2>(*range_cache)[ip - std::get<1>(*range_cache).start]++;
        } else {
            for(auto &tuple : m) {
                if(ip >=  std::get<1>(tuple).start && ip <= std::get<1>(tuple).end) {
                    in = true;
                    range_cache = &tuple;
                    std::get<2>(*range_cache)[ip - std::get<1>(*range_cache).start]++;
                }
            }
        }

        if(!in) {
            m = ptraceProf::orderMap::getProcessCount(pid);
            for(auto &tuple : m) {
                if(ip >=  std::get<1>(tuple).start && ip <= std::get<1>(tuple).end) {
                    in = true;
                    range_cache = &tuple;
                    std::get<2>(*range_cache)[ip - std::get<1>(*range_cache).start]++;
                }
            }
            if(!in) {
                std::cerr << "meet error rip " << ip << " in no file " << std::endl;
                exit(1);
            }
        }
    }
}

int main() {
    int child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        execl("/bin/ls", "ls");
        // execl("./a.out", "out");
    } else {
        // some_time_trace(child);
        dump_and_trace(child);
    }
}
