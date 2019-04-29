#pragma once
#include "orderMap.hpp"
#include "mapsReader.hpp"
#include <map>
#include <set>
#include <unordered_map>
#include <sys/types.h> // pid_t
#include <sys/reg.h> // RIP
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <dirent.h> // opendir
#include <unistd.h>
#include <stdio.h>

namespace ptraceProf {

class processProf {
private:
    using maps = ::ptraceProf::mapsReader::result_t;
    using orders = ::ptraceProf::orderMap::result_t;
    using mem_range = ::ptraceProf::mapsReader::mem_range;

    // using result_t = std::vector < std::tuple<
    // std::string, mem_range,
    // std::vector<std::map<unsigned long long ,unsigned int> >
    // > >;
    using ip_t = unsigned long long;

    std::vector<orders> ans;
    // std::map<std::string, std::vector<mem_range> >
    maps file_map;

    std::map<pid_t, orders> pid_order;
    std::map<pid_t, ip_t> lastcommand;
    std::map<pid_t, orders::iterator> range_cache;

    std::unordered_map<ip_t, bool> need_singlestep;
    std::unordered_map<ip_t, int> direct_count;
public:
    static bool start_with(const std::string &base, const std::string &head) {
        for(int i = 0; i < head.size(); ++i) {
            if(base[i] != head[i]) {
                return false;
            }
        }
        return true;
    }

    static int force_jump(const std::string &info) {
        if(info.size() == 0) {
            return 0;
        }
        if(start_with(info, "bnd ")) {
            return force_jump(info.substr(4));
        }
        std::vector<std::string> force_jump_list = {
            "callq", "jmpq", "retq", "repz", "syscall"
        };
        for(auto front : force_jump_list) {
            if(start_with(info, front)) {
                if(info.size() <= 7) {
                    return -1;
                }
                int adder = -1;
                std::stringstream ss(info.substr(7));
                ss >> std::hex >> adder;
                return adder;
            }
        }
        return 0;
    }

    static unsigned int may_jump(const std::string &info) {
        if(info.size() == 0) {
            return 0;
        }
        if(start_with(info, "bnd ")) {
            return may_jump(info.substr(4));
        }
        std::vector<std::string> may_jump_list = {
            "jo", "jno", "jc", "jnc", "jz", "je", "jnz", "jne", "js", "jns",
            "jp", "jpe", "jnp", "jpo", "jb", "jnae", "jnb", "jae", "jbe", "jna",
            "jnbe", "ja", "jl", "jnge", "jnl", "jge", "jle", "jng", "jnle", "jg"
        };
        if(info[0] != 'j') {
            return 0;
        }
        for(auto front : may_jump_list) {
            if(start_with(info, front)) {
                std::stringstream ss(info.substr(front.size() + 1));
                unsigned int addr;
                ss >> std::hex >> addr;
                return addr;
            }
        }
        return 0;
    }

    static std::string lltoString(long long t) {
        std::string result;
        std::stringstream ss;
        ss << " " << std::hex << t << " ";
        ss >> result;
        return result;
    }

    static bool may_jump(const std::string &info, const unsigned long long next_addre) {
        auto add = lltoString(next_addre);
        return info.find(add) != std::string::npos;
    }

    static auto update_singlestep_map(const std::map< unsigned int, std::tuple <
                                      std::vector<unsigned short>,
                                      std::string > > &block) {
        std::set<unsigned int> ans;
        if(block.empty()) {
            return ans;
        }

        unsigned int block_start = block.begin()->first;
        // 当前块的路径
        std::set<unsigned int> has;
        // 条件跳转的出口
        std::set<unsigned int> outs;

        for(auto [addre, _] : block) {
            // std::cout << std::hex << addre << std::endl;
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
            }
        }
        return ans;
    }

    static auto update_singlestep_map(const std::string &file) {
        using ::ptraceProf::get_cmd_stream;
        auto fs = get_cmd_stream("objdump -d " + file);
        std::set<unsigned int>ans;
        while(fs) {
            auto need_siglestep  = update_singlestep_map(::ptraceProf::dumpReader::read_block(fs));
            ans.merge(need_siglestep);
        }
        return ans;
    }

    void stop_trace(const pid_t pid) {
        pid_order.erase(pid);
        lastcommand.erase(pid);
        range_cache.erase(pid);
    }

    void reflush_map(const pid_t pid) {
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
            if (!::ptraceProf::orderMap::file_exist(file)){
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

    static inline ip_t get_ip(const pid_t pid) {
        return ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
    }

    inline bool check_process(const pid_t pid) {
        if(kill(pid, 0)) {
            // process not run
            // https://stackoverflow.com/questions/11785936/how-to-find-if-a-process-is-running-in-c
            // process never run ,stop trace and save ans
            this->ans.push_back(pid_order.at(pid));
            return false;
        }
        // error catch
        // it shouldn`t happen
        fprintf(stderr, "the pid : %d can not trace but can kill\nIt shouldn`t happened\n", pid);
        exit(1);
        return true;
    }

    inline bool singleblock(const pid_t pid) {
        int status = 0;
        ptrace(PTRACE_SINGLEBLOCK, pid, 0, 0);
        if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
            return check_process(pid);
        }
        return true;
    }

    inline bool singlestep(const pid_t pid) {
        int status = 0;
        ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
        if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
            return check_process(pid);
        }
        return true;
    }

    bool process_pause(const int pid) {
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

    void procsss_start(const int pid) {
        lastcommand[pid] = 0;
        if(ptrace(PTRACE_DETACH, pid, 0, 0)) {
            fprintf(stderr, "fail to detach pid :%d\n", pid);
            check_process(pid);
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

    inline static bool in_range(const ip_t ip, const mem_range &range) {
        return ip > range.start && ip < range.end;
    }

    auto find_range(const ip_t pid, const ip_t ip) {
        for(auto it = this->pid_order[pid].begin(); it != pid_order[pid].end(); ++it) {
            auto &range = std::get<1>(*it);
            if(in_range(ip, range)) {
                return it;
            }
        }
        return pid_order[pid].end();
    }

    bool ptrace_once(const pid_t pid) {
        if(this->singleblock(pid)) {
            auto ip = get_ip(pid);
            if(this->need_singlestep[ip]) {
                this->direct_count[ip] += 1;
                while(this->need_singlestep[ip]) {
                    if(this->singlestep(pid)) {
                        ip = get_ip(pid);
                        this->direct_count[ip] += 1;
                    } else {
                        return false;
                    }
                }
                lastcommand[pid] = ip;
                return true;
            } 
            // else {
                if(range_cache[pid] == this->pid_order[pid].end() || !in_range(ip, std::get<1>(*range_cache[pid]))) {
                    // no hit cache
                    auto it = find_range(pid, ip);
                    if(it == pid_order[pid].end()) {
                        // if no found rip in maps reload maps and try again
                        // TODO 增量式maps读取
                        this->reflush_map(pid);
                        it = find_range(pid, ip);
                        // TODO error detect
                    }
                    range_cache[pid] = it;
                }
                if(lastcommand[pid]) {
                    auto it = range_cache[pid];
                    auto &a = std::get<2>(*it);
                    auto &b = a[ip - std::get<1>(*it).start];
                    b[lastcommand[pid]]++;
                    lastcommand[pid] = ip;
                } else {
                    lastcommand[pid] = ip;
                }
                return true;
            // }
        }
        return false;
    }

    void trace(const pid_t pid) {
        range_cache[pid] = pid_order[pid].end();
        while(ptrace_once(pid)) {}
    }

    auto get_ans()const {
        std::map<std::pair<ip_t, ip_t>, unsigned int> result;
        for(const auto &order_result : ans) {
            for(const auto&[filename, mem_range, start_count] : order_result) {
                for(unsigned int i = 0; i < start_count.size(); ++i) {
                    for(auto [start_ip, times] : start_count[i]) {
                        const ip_t end_ip = i + mem_range.start;
                        result[std::make_pair(start_ip, end_ip)] += times;
                    }
                }
            }
        }
        return result;
    }
    auto get_direct_count(std::map<std::string, std::map<std::string, int> > result = {})const {
        for(auto [ip, times] : this->direct_count) {
            for(auto [file, ranges] : file_map) {
                for(auto range : ranges) {
                    if(in_range(ip, range)) {
                        result[file][lltoString(ip - range.start + range.offset)] += times;
                    }
                }
            }
        }
        return result;
    }

    const auto &get_file_map()const {
        return this->file_map;
    }
};

} // namespace ptraceProf
