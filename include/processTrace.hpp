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

    std::unordered_map<ip_t, std::unordered_map<ip_t, std::unordered_map<ip_t, long long> > > ans;
    // std::map<std::string, std::vector<mem_range> >
    maps file_map;

    std::map<pid_t, orders> pid_order;
    std::map<pid_t, ip_t> lastcommand;
    std::map<pid_t, orders::iterator> range_cache;

    std::unordered_map<ip_t, bool> need_singlestep;
    std::unordered_map<ip_t, int> direct_count;
public:
    static bool start_with(const std::string &base, const std::string &head);

    static int force_jump(const std::string &info);

    static unsigned int may_jump(const std::string &info);

    static std::string lltoString(long long);

    static bool may_jump(const std::string &info, const unsigned long long next_addre);

    static std::set<unsigned int> update_singlestep_map(const std::map< unsigned int, std::tuple <
            std::vector<unsigned short>,
            std::string > > &block);

    static std::set<unsigned int> update_singlestep_map(const std::string &file);

    void stop_trace(const pid_t pid);

    void reflush_map(const pid_t pid);

    static inline ip_t get_ip(const pid_t pid) {
        return ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
    }

    bool check_process(const pid_t pid);

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

    static std::vector<pid_t> ListThreads(pid_t pid);

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

    bool ptrace_once(const pid_t pid);

    void trace(const pid_t pid) {
        range_cache[pid] = pid_order[pid].end();
        while(ptrace_once(pid)) {}
    }

    std::map<std::pair<ip_t, ip_t>, unsigned int> get_ans()const {
        std::map<std::pair<ip_t, ip_t>, unsigned int> result;
        for(const auto &[pid, order_result] : ans) {
            for(const auto[startip, outs] : order_result) {
                for(const auto[endip, times] : outs) {
                    result[std::make_pair(startip, endip)] += times;
                }

            }
        }
        return result;
    }

    std::pair<std::string, unsigned int>get_offset_and_file_by_ip(const ip_t ip) const {
        for(auto [file, ranges] : file_map) {
            for(auto range : ranges) {
                if(in_range(ip, range)) {
                    return std::make_pair(file, (ip - range.start + range.offset));
                }
            }
        }
        return std::make_pair(std::string(), 0);
    }

    auto get_direct_count(std::map<std::string, std::map<std::string, int> > result = {})const {
        for(auto [ip, times] : this->direct_count) {
            auto [file, offset] = get_offset_and_file_by_ip(ip);
            result[file][lltoString(offset)] += times;
        }
        return result;
    }

    const auto &get_file_map()const {
        return this->file_map;
    }
};

} // namespace ptraceProf
