#include "processTrace.hpp"

#include <sys/types.h> // pid_t
#include <sys/reg.h> // RIP
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <dirent.h> // opendir
#include <unistd.h>
#include <stdio.h>

namespace ptraceProf {

processProf::ip_t processProf::get_ip(const pid_t pid) {
#ifdef __x86_64__
    return ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
#else
    return ptrace(PTRACE_PEEKUSER, pid, 4 * EIP, NULL);
#endif
}

bool processProf::singleblock(const pid_t pid) {
    int status = 0;
    ptrace(PTRACE_SINGLEBLOCK, pid, 0, 0);
    if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
        return check_process(pid);
    }
    return true;
}

bool processProf::singlestep(const pid_t pid) {
    int status = 0;
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
        return check_process(pid);
    }
    return true;
}

bool processProf::process_pause(const pid_t pid) {
    if(ptrace(PTRACE_ATTACH, pid, 0, 0)) {
        fprintf(stderr, "process %d cannot attach\n", pid);
        return check_process(pid);
    }
    int status;
    if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
        return check_process(pid);
    }
    return true;
}

bool processProf::procsss_start(const pid_t pid) {
    lastcommand[pid] = 0;
    if(ptrace(PTRACE_DETACH, pid, 0, 0)) {
        fprintf(stderr, "fail to detach pid :%d\n", pid);
        return check_process(pid);
    }
}

bool processProf::start_with(const std::string &base, const std::string &head) {
    for(int i = 0; i < head.size(); ++i) {
        if(base[i] != head[i]) {
            return false;
        }
    }
    return true;
}

int processProf::force_jump(const std::string &info) {
    if(info.size() == 0) {
        return 0;
    }
    if(start_with(info, "bnd ")) {
        return force_jump(info.substr(4));
    }
    std::vector<std::string> force_jump_list = {
        "callq", "jmpq", "retq", "syscall", "jmp "
    };
    for(auto front : force_jump_list) {
        if(start_with(info, front)) {
            if(info.size() <= 7) {
                return -1;
            }
            int adder = -1;
            std::stringstream ss(info.substr(7));
            if(ss >> std::hex >> adder) {
                return adder;
            } else {
                return -1;
            }
        }
    }
    return 0;
}

bool processProf::need_check(const std::string &info) {
    if(start_with(info, "rep ")) {
        return true;
    } else if(start_with(info, "repz ")) {
        return true;
    } else if(start_with(info, "repe ")) {
        return true;
    }
    return false;
}

unsigned int processProf::may_jump(const std::string &info) {
    if(info.size() == 0) {
        return 0;
    }
    if(start_with(info, "bnd ")) {
        return may_jump(info.substr(4));
    }
    const std::vector<std::string> may_jump_list = {
        "jo", "jno", "jc", "jnc", "jz", "je", "jnz", "jne", "js", "jns",
        "jp", "jpe", "jnp", "jpo", "jb", "jnae", "jnb", "jae", "jbe", "jna",
        "jnbe", "ja", "jl", "jnge", "jnl", "jge", "jle", "jng", "jnle", "jg"
    };
    if(info[0] != 'j') {
        return 0;
    }
    for(const std::string &front : may_jump_list) {
        if(start_with(info, front)) {
            std::stringstream ss(info.substr(front.size() + 1));
            std::string s = ss.str();
            unsigned int addr = 0;
            ss >> std::hex >> addr;
            return addr;
        }
    }
    return 0;
}

std::string processProf::lltoString(long long t) {
    std::string result;
    std::stringstream ss;
    ss << " " << std::hex << t << " ";
    ss >> result;
    return result;
}

bool processProf::may_jump(const std::string &info, const unsigned long long next_addre) {
    auto add = lltoString(next_addre);
    return info.find(add) != std::string::npos;
}

std::set<unsigned int>processProf::update_singlestep_map(const std::map< unsigned int, std::tuple <
        std::vector<unsigned short>,
        std::string > > &block) {
    std::set<unsigned int> ans;
    if(block.size()) {
        // 当前块的路径
        std::set<unsigned int> has;
        // 条件跳转的出口
        std::set<unsigned int> outs;
        for(auto [addre, _] : block) {
            auto [__, info] = _;
            has.insert(addre);
            unsigned int out = 0;
            if((out = force_jump(info)) != 0) {
                if(outs.find(out) != outs.end()) {
                    // 如果已经有这个寻址点的出口，标记当前队列中所有地址
                    for(auto point : has) {
                        ans.insert(point);
                    }
                }
                has.clear();
                outs.clear();
            } else if((out = may_jump(info)) != 0) {
                if(outs.find(out) != outs.end()) {
                    // 如果已经有这个寻址点的出口，标记当前队列中所有地址
                    for(auto point : has) {
                        ans.insert(point);
                    }
                } else {
                    outs.insert(out);
                }
            } else if(need_check(info)) {
                // 如果当前语句需要单步检查，标记队列中包括本句在内的所有语句
                for(auto point : has) {
                    ans.insert(point);
                }
                ans.insert(addre);
            }
        }
    }
    return ans;
}

std::set<unsigned int> processProf::update_singlestep_map(const std::string &file) {
    using ::ptraceProf::get_cmd_stream;
    auto fs = get_cmd_stream("objdump -d " + file);
    std::set<unsigned int>ans;
    while(fs) {
        auto need_siglestep  = update_singlestep_map(::ptraceProf::dumpReader::read_block(fs));
        ans.merge(need_siglestep);
    }
    return ans;
}

void processProf::stop_trace(const pid_t pid) {
    pid_order.erase(pid);
    lastcommand.erase(pid);
    range_cache.erase(pid);
}

void processProf::reflush_map(const pid_t pid) {
    using ::ptraceProf::mapsReader::readMaps;
    using ::ptraceProf::orderMap::getProcessCount;
    file_map = readMaps(pid);
    for(auto &order : this->pid_order) {
        getProcessCount(pid, order.second);
    }
    for(auto &[pid, cache] : range_cache) {
        cache = pid_order[pid].end();
    }
    this->need_singlestep.clear();
    for(auto [file, ranges] : file_map) {
        if(!::ptraceProf::orderMap::file_exist(file)) {
            continue;
        }
        auto list = update_singlestep_map(file);
        for(auto addre : list) {
            for(auto range : ranges) {
                if(addre > range.offset && addre - range.offset + range.start < range.end) {
                    need_singlestep[addre - range.offset + range.start] = true;
                }
            }
        }
    }
}

std::vector<pid_t> processProf::ListThreads(pid_t pid) {
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

bool processProf::check_process(const pid_t pid) {
    if(kill(pid, 0)) {
        // process not run
        // https://stackoverflow.com/questions/11785936/how-to-find-if-a-process-is-running-in-c
        // process never run ,stop trace and save ans
        return false;
    }
    // error catch
    // it shouldn`t happen
    fprintf(stderr, "the pid : %d can not trace but can kill\nIt shouldn`t happened\n", pid);
    exit(1);
    return true;
}

bool processProf::ptrace_once(const pid_t pid) {
    if(lastcommand[pid] && !need_singlestep[lastcommand[pid]]) {
        if(this->singleblock(pid)) {
            auto ip = get_ip(pid);
            auto [file, offset] = get_offset_and_file_by_ip(ip, pid);
            std::cerr << "noral " << file << "\t" << lltoString(offset) << '\n';
            if(lastcommand[pid]) {
                std::cerr << "setin ";
                std::tie(file, offset) = get_offset_and_file_by_ip(lastcommand[pid], pid);
                std::cerr << file << "\t" << lltoString(offset) << "\tto ";
                std::tie(file, offset) = get_offset_and_file_by_ip(ip, pid);
                std::cerr << file << "\t" << lltoString(offset) << '\n';
                this->ans[pid][lastcommand[pid]][ip] ++;
            }
            lastcommand[pid] = ip;
            return true;
        } else {
            return false;
        }
    } else {
        if(lastcommand[pid]) {
            this->direct_count[lastcommand[pid]]++;
        }
        if(this->singlestep(pid)) {
            const auto ip = get_ip(pid);
            auto[file, offset] = get_offset_and_file_by_ip(ip, pid);
            std::cerr << "insin " << file << "\t" << lltoString(offset) << std::endl;
            lastcommand[pid] = ip;
            return true;
        }
    }
    return false;
}


}