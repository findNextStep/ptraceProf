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

    static bool need_check(const std::string &info);

    static std::string lltoString(long long);

    static bool may_jump(const std::string &info, const unsigned long long next_addre);

    static std::set<unsigned int> update_singlestep_map(const std::map< unsigned int, std::tuple <
            std::vector<unsigned short>,
            std::string > > &block);

    static std::set<unsigned int> update_singlestep_map(const std::string &file);

    static ip_t get_ip(const pid_t pid);

    static std::vector<pid_t> ListThreads(pid_t pid);

    inline static bool in_range(const ip_t ip, const mem_range &range) {
        return ip > range.start && ip < range.end;
    }


    static bool no_run(const std::string &info) {
        return !info.size();
    }

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

    std::pair<std::string, unsigned int>get_offset_and_file_by_ip(const ip_t ip, const pid_t pid) {
        auto ans = get_offset_and_file_by_ip(ip);
        if(ans.first.size()) {
            return ans;
        }
        reflush_map(pid);
        return get_offset_and_file_by_ip(ip);
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

public:
    const auto &get_file_map()const {
        return this->file_map;
    }
    void trace(const pid_t pid) {
        range_cache[pid] = pid_order[pid].end();
        while(ptrace_once(pid)) {}
    }

    std::map<std::string, std::map<int, std::map<int, int> > > analize_trace();

    std::map<std::string, std::map<std::string, int> > analize(std::map<std::string, std::map<std::string, int> > result = {});
};

} // namespace ptraceProf
