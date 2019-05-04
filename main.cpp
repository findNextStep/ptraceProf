#include <iostream>
#include "orderMap.hpp"
#include "readDump.hpp"
#include "processTrace.hpp"
#include <nlohmann/json.hpp>
#include <sstream>
#include <time.h>
#include <sys/user.h>
#include <thread>
#include "gethin.hpp"
#include <sys/types.h> // pid_t
#include <sys/reg.h> // RIP
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <dirent.h> // opendir
#include <unistd.h>
#include <stdio.h>

std::string lltoString(long long t) {
    std::string result;
    std::stringstream ss;
    ss << std::hex << t;
    ss >> result;
    return result;
}

std::pair<std::string, unsigned long long> _find_it(const ::ptraceProf::mapsReader::result_t &file_map, unsigned long long ip) {
    for(const auto &[file, ranges] : file_map) {
        for(const auto range : ranges) {
            if(::ptraceProf::processProf::in_range(ip, range)) {
                return std::make_pair(file, ip - range.start + range.offset);
            }
        }
    }
    return std::make_pair(std::string(), 0);
}

auto dump_and_trace_sign(const int pid) {
    int status = -1;
    wait(&status);
    auto maps = ::ptraceProf::mapsReader::readMaps(pid);
    //{filename:{addre(hex),time}}
    std::map<std::string, std::map<std::string, int> > ans;
    while(1) {
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
            if(kill(pid, 0)) {
                break;
            }
            fprintf(stderr, "fail to wait pid :%d process may exited\n", pid);
            fprintf(stderr, "the tracer process will continue\n");
            break;
        }
        long ip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
        auto [file, offset] = _find_it(maps, ip);
        if(file == "") {
            maps = ::ptraceProf::mapsReader::readMaps(pid);
            std::tie(file, offset) = _find_it(maps, ip);
        }
        ans[file][lltoString(offset)]++;

        // struct user_regs_struct regs;
        // ptrace(PTRACE_GETREGS,pid,nullptr,&regs);
        std::cerr << lltoString(offset) << '\t' << file << '\n';
    }
    return ans;
}

int main(int argc, char **argv) {
    gethin::Flag single_step = gethin::Flag()
                               .shortOpt('s')
                               .longOpt("single_step")
                               .help("decisiion whether use single step test");
    gethin::String step_file = gethin::String()
                               .longOpt("step-file")
                               .help("output file for process step. If no set ,while output to stderr");
    gethin::String final_result_file = gethin::String()
                                       .shortOpt('r')
                                       .longOpt("final_result_file")
                                       .help("the file for ans as {file:[offset,time]} in json. If no set, won`t output");
    gethin::String exec_path = gethin::String()
                               .longOpt("exec_path")
                               .shortOpt('c')
                               .help("exeable file path. will be ./a.out in default");
    gethin::OptionReader optReader({
        &single_step,
        &step_file,
        &final_result_file,
        &exec_path,
    }, "ptraceProf");
    try {
        optReader.read(argc, argv);
    } catch(const std::invalid_argument &e) {
        std::cerr << e.what() << std::endl;
        return 1;
    } catch(...) {
        std::cerr << "Error during execution!" << std::endl;
        return 1;
    }

    int child = fork();
    if(child == 0) {
        // in tracee process
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        if(exec_path.value().empty()) {
            execl("./a.out", "out");
        } else {
            execl(exec_path.value().c_str(), "tracee");
        }
    }
    // in tracer porcess
    std::cout << "child_pid == " << child;
    std::map<std::string, std::map<std::string, int> > ans;
    // command line value check
    if(step_file.value().size()) {
        freopen(step_file.value().c_str(), "w", stderr);
    }
    ::ptraceProf::processProf pp;
    if(single_step.value()) {
        std::cout << "in single step";
        ans = dump_and_trace_sign(child);
    } else {
        std::cout << "in block step";
        pp.trace(child);
    }
    std::cout << "finish" << std::endl;
    if(final_result_file.value().size()) {
        if(!single_step.value()) {
            ans = pp.analize();
        }
        std::ofstream of(final_result_file.value());
        of << ::nlohmann::json(ans).dump(4);
    }
    return 0;
}


