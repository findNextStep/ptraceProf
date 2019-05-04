#pragma once

#include "pipe.hpp"
#include "orderMap.hpp"
#include "mapsReader.hpp"

#include <map>
#include <set>
#include <unordered_map>
#include <vector>

#include <thread>

namespace ptraceProf {
using ip_t = unsigned long long;
using maps = ::ptraceProf::mapsReader::result_t;
using orders = ::ptraceProf::orderMap::result_t;
using mem_range = ::ptraceProf::mapsReader::mem_range;

bool start_with(const std::string &base, const std::string &head);

int force_jump(const std::string &info);

unsigned int may_jump(const std::string &info);

bool need_check(const std::string &info);

std::string lltoString(long long);

ip_t get_ip(const pid_t pid);

std::vector<pid_t> ListThreads(pid_t pid);

void ptraceThisProcess();

inline bool in_range(const ip_t ip, const mem_range &range) {
    return ip > range.start && ip < range.end;
}


inline bool no_run(const std::string &info) {
    return !info.size();
}

std::pair<std::string, ip_t> find_file_and_offset(const ::ptraceProf::mapsReader::result_t &file_map, const ip_t ip);

std::pair<std::unordered_map<ip_t, unsigned long long>, maps> dump_and_trace_sign(const int pid);

std::map<std::string, std::map<std::string, int> > analize(const std::unordered_map<ip_t, unsigned long long> &count, const maps &map);

static bool may_jump(const std::string &info, const unsigned long long next_addre);
class processProf {
private:

    // using result_t = std::vector < std::tuple<
    // std::string, mem_range,
    // std::vector<std::map<unsigned long long ,unsigned int> >
    // > >;

    std::unordered_map<ip_t, std::unordered_map<ip_t, std::unordered_map<ip_t, long long> > > ans;
    // std::map<std::string, std::vector<mem_range> >
    maps file_map;

    std::map<pid_t, orders> pid_order;
    std::map<pid_t, ip_t> lastcommand;
    std::map<pid_t, orders::iterator> range_cache;

    std::unordered_map<ip_t, bool> need_singlestep;
    std::unordered_map<ip_t, int> direct_count;
public:


    static std::set<unsigned int> update_singlestep_map(const std::map< unsigned int, std::tuple <
            std::vector<unsigned short>,
            std::string > > &block);

    static std::set<unsigned int> update_singlestep_map(const std::string &file);


protected:
    void stop_trace(const pid_t pid);
    void reflush_map(const pid_t pid);
    bool check_process(const pid_t pid);
    inline bool singleblock(const pid_t pid);
    inline bool singlestep(const pid_t pid);
    bool process_pause(const int pid);
    bool procsss_start(const int pid);


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

    void checkip(const ip_t ip, const pid_t pid);

    std::pair<std::string, unsigned int>get_offset_and_file_by_ip(const ip_t ip, const pid_t pid) {
        auto ans = get_offset_and_file_by_ip(ip);
        if(ans.first.size()) {
            return ans;
        }
        reflush_map(pid);
        return get_offset_and_file_by_ip(ip);
    }
    std::pair<std::string, unsigned int>get_offset_and_file_by_ip(const ip_t ip) const {
        return find_file_and_offset(this->file_map, ip);
    }

public:
    void trace(const pid_t pid) {
        range_cache[pid] = pid_order[pid].end();
        while(ptrace_once(pid)) {}
    }

    std::map<std::string, std::map<int, std::map<int, int> > > analize_trace();

    std::map<std::string, std::map<std::string, int> > analize(std::map<std::string, std::map<std::string, int> > result = {});
};

} // namespace ptraceProf
