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

int main() {
    int child = fork();
    if(child == 0) {
        execl("/bin/ls", "ls");
        // execl("./a.out", "out");
    } else {
        some_time_trace(child);
    }
}
