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

auto dump_and_trace(const int pid) {
    int status = -1;
    wait(&status);
    if(WIFEXITED(status)) { //子进程发送退出信号，退出循环
        return ::ptraceProf::orderMap::result_t();
    }
    auto m = ptraceProf::orderMap::getProcessCount(pid);
    auto range_cache = &m[0];
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    // wait(&status);
    if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
        if(kill(pid, 0)) {
            // process not run
            // https://stackoverflow.com/questions/11785936/how-to-find-if-a-process-is-running-in-c
            return m;
        }
        fprintf(stderr, "fail to wait pid :%d process may exited\n", pid);
        fprintf(stderr, "the tracer process will continue\n");
        return m;
    }
    long last_command = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
    while(1) {
        ptrace(PTRACE_SINGLEBLOCK, pid, 0, 0);
        // wait(&status);
        if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
            if(kill(pid, 0)) {
                // process not run
                // https://stackoverflow.com/questions/11785936/how-to-find-if-a-process-is-running-in-c
                break;
            }
            fprintf(stderr, "fail to wait pid :%d process may exited\n", pid);
            fprintf(stderr, "the tracer process will continue\n");
            break;
        }
        long ip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
        bool in = false;
        if(ip >= std::get<1>(*range_cache).start && ip <= std::get<1>(*range_cache).end) {
            in = true;
            std::get<2>(*range_cache)[ip - std::get<1>(*range_cache).start][last_command]++;
            last_command = ip;
        } else {
            for(auto &tuple : m) {
                if(ip >=  std::get<1>(tuple).start && ip <= std::get<1>(tuple).end) {
                    in = true;
                    range_cache = &tuple;
                    std::get<2>(*range_cache)[ip - std::get<1>(*range_cache).start][last_command]++;
                    last_command = ip;
                }
            }
        }
        if(!in) {
            ptraceProf::orderMap::getProcessCount(pid, m);
            for(auto &tuple : m) {
                if(ip >=  std::get<1>(tuple).start && ip <= std::get<1>(tuple).end) {
                    in = true;
                    range_cache = &tuple;
                    std::get<2>(*range_cache)[ip - std::get<1>(*range_cache).start][last_command]++;
                    last_command = ip;
                }
            }
            if(!in) {
                std::cerr << "meet error rip " << ip << " in no file " << std::endl;
                exit(1);
            }
        }
    }
    return m;
}

auto analize_trace(const ::ptraceProf::orderMap::result_t &result) {
    auto &cout = std::cerr;
    cout << "start analize" << std::endl;
    using std::endl;
    std::string last_file = "";
    for(const auto &item : result) {
        if(last_file != std::get<0>(item)) {
            last_file = std::get<0>(item);
            cout << last_file << " :\n";
        }
        auto start = std::get<1>(item).start;
        const auto &li = std::get<2>(item);
        for(auto i = 0; i < li.size(); ++i) {
            for (auto jmp : li[i]){
                cout << std::hex << i << " --> " << jmp.first << " : " << std::dec << jmp.second << endl;
            }
        }
    }
}

int main() {
    int child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // execl("/bin/ls", "ls");
        execl("./a.out", "out");
    } else {
        // some_time_trace(child);
        analize_trace(dump_and_trace(child));
    }
}
