#pragma once

#include "pipe.hpp"
#include "orderMap.hpp"
#include "mapsReader.hpp"
#include "readDump.hpp"


#include <map>
#include <set>
#include <unordered_map>
#include <vector>

#include <thread>

namespace ptraceProf {
using ip_t = unsigned long long;
using count_t = unsigned long long;
using direct_count_t = std::unordered_map<ip_t, count_t>;
using block_count_t = std::unordered_map<ip_t, direct_count_t >;
using result_t = std::map<std::string, std::map<std::string, count_t> >;
using maps = ::ptraceProf::mapsReader::result_t;
using orders = ::ptraceProf::orderMap::result_t;
using mem_range = ::ptraceProf::mapsReader::mem_range;

bool start_with(const std::string &base, const std::string &head);

ip_t force_jump(const std::string &info);

ip_t may_jump(const std::string &info);

bool may_jump(const std::string &info, const ip_t next_addre);

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

bool is_dynamic_file(const std::string &file);

std::pair<std::string, ip_t> find_file_and_offset(const maps &file_map, const ip_t ip);

std::pair<direct_count_t, maps> dump_and_trace_sign(const int pid);

result_t analize(const maps &map, const direct_count_t &count);

result_t analize(
    const std::map<std::string, std::map<ip_t, std::map<ip_t, count_t> > > &ans);

result_t analize( const maps &map, const block_count_t &ans);


result_t analize(const maps &map, const direct_count_t &count, const block_count_t &dir);

class processProf {
private:

    // using result_t = std::vector < std::tuple<
    // std::string, mem_range,
    // std::vector<std::map<unsigned long long ,unsigned int> >
    // > >;

    std::unordered_map<pid_t, block_count_t > ans;
    // std::map<std::string, std::vector<mem_range> >
    maps file_map;

    std::map<pid_t, orders> pid_order;
    std::map<pid_t, ip_t> lastcommand;

    std::unordered_map<ip_t, bool> need_singlestep;
    direct_count_t direct_count;
public:


    static std::set<ip_t> update_singlestep_map(const std::map< unsigned int, std::tuple < order_t, std::string > > &block);

    static std::set<ip_t> update_singlestep_map(const std::string &file);


protected:
    void stop_trace(const pid_t pid);
    void reflush_map(const pid_t pid);
    bool check_process(const pid_t pid);
    inline bool singleblock(const pid_t pid);
    inline bool singlestep(const pid_t pid);
    bool process_pause(const pid_t pid);
    bool procsss_start(const pid_t pid);

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
    inline std::pair<std::string, unsigned int>get_offset_and_file_by_ip(const ip_t ip) const {
        return find_file_and_offset(this->file_map, ip);
    }

public:
    void trace(const pid_t pid) {
        while(ptrace_once(pid)) {}
    }

    result_t analize() const;
};


} // namespace ptraceProf
