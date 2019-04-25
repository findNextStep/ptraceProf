#pragma once
#include "orderMap.hpp"
#include "mapsReader.hpp"
#include <map>
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
public:
    using maps = ::ptraceProf::mapsReader::result_t;
    using orders = ::ptraceProf::orderMap::result_t;
    using mem_range = ::ptraceProf::mapsReader::mem_range;

    // using result_t = std::vector < std::tuple<
    // std::string, mem_range,
    // std::vector<std::map<unsigned long long ,unsigned int> >
    // > >;
    using ip_t = unsigned long long;

    std::vector<orders> ans;
    maps file_map;

    std::map<pid_t, orders> pid_order;
    std::map<pid_t, ip_t> lastcommand;
    std::map<pid_t, orders::iterator> range_cache;
public:
    processProf(const pid_t pid) {}

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
        if(!this->singleblock(pid)) {
            return false;
        } else {
            const auto ip = get_ip(pid);
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
        }
    }

    void trace(const pid_t pid) {
        range_cache[pid] = pid_order[pid].end();
        while(ptrace_once(pid)) {}
    }

    auto get_ans()const {
        std::map<std::pair<ip_t, ip_t>, unsigned int> result;
        for(const auto &order_result : ans) {
            for(const auto&[filename, mem_range, start_count] : order_result) {
                for (unsigned int i = 0;i<start_count.size();++i){
                    for (auto [start_ip,times]:start_count[i]){
                        const ip_t end_ip = i + mem_range.start;
                        result[std::make_pair(start_ip,end_ip)] += times;
                    }
                }
            }
        }
        return result;
    }
};

} // namespace ptraceProf
