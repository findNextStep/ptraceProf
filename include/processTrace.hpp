#pragma once

#include "typedef.hpp"
#include "pipe.hpp"
#include "orderMap.hpp"
#include "mapsReader.hpp"
#include "readDump.hpp"
#include "dumpCache.hpp"

#include <map>
#include <set>
#include <unordered_map>
#include <vector>
#include <chrono>

#include <thread>

namespace ptraceProf {
/* the count for signle ip */
using direct_count_t = std::unordered_map<ip_t, count_t>;
/* the count for a block */
using block_count_t = std::unordered_map<ip_t, direct_count_t >;
/**
 * @brief the result for prof
 * {"linked file":{"objdump address in hex": count}}
 */
using result_t = std::map<std::string, std::map<std::string, count_t> >;
using maps = ::ptraceProf::mapsReader::result_t;
using orders = ::ptraceProf::orderMap::result_t;
using mem_range = ::ptraceProf::mapsReader::mem_range;

/**
 * @brief get_ip get ip point for pid
 *
 * @param pid the process we want to trace
 *
 * @return ip point address
 */
ip_t get_ip(const pid_t pid);

/**
 * @brief ListThreads list the threads for one process
 *
 * @param pid the process in the process
 *
 * @return the pid list
 */
std::vector<pid_t> ListThreads(pid_t pid);

/**
 * @brief ptraceThisProcess make the process traceable
 */
void ptraceThisProcess();

/**
 * @brief in_range if the ip point address is in a memery range
 *
 * @param ip point address
 * @param range a memery rage
 *
 * @return if the ip is in range
 */
inline bool in_range(const ip_t ip, const mem_range &range) {
    return ip > range.start && ip < range.end;
}


/**
 * @brief no_run check the command is not run
 * is for bolck result to final result
 * @param info command info from objdump
 *
 * @return if the command need run
 */
inline bool no_run(const std::string &info) {
    return !info.size();
}

/**
 * @brief is_dynamic_file check the file if the file is dynamic link
 *
 * @param file file name
 *
 * @return if the file is dynamic link
 */
bool is_dynamic_file(const std::string &file);

/**
 * @brief find_file_and_offset find file and offset that the ip address map to
 *
 * @param file_map file map that in /proc/<pid>/maps
 * @param ip ip address
 *
 * @return <file name,offset>
 */
std::pair<std::string, ip_t> find_file_and_offset(const maps &file_map, const ip_t ip);

/**
 * @brief dump_and_trace_sign simple trace use single step
 *
 * @param pid process pid
 *
 * @return <direct count, file map>
 */
std::pair<direct_count_t, maps> dump_and_trace_sign(const int pid);

/**
 * @brief analize analize the drirect count by file map
 *
 * @param map file map
 * @param count direct count
 *
 * @return result
 */
result_t analize_count(const maps &map, const direct_count_t &count);

/**
 * @brief analize change block result to result
 *
 * @param ans {file:{start_ip:{end_ip,times}}}
 *
 * @return result
 */
result_t analize_count(const std::map<std::string, std::map<ip_t, std::map<ip_t, count_t> > > &ans);

/**
 * @brief analize analize block result
 *
 * @param map file map
 * @param ans block analize result
 *
 * @return result
 */
result_t analize_count(const maps &map, const block_count_t &ans);


/**
 * @brief analize analize block result and single result to result
 *
 * @param map file map
 * @param count direct count
 * @param dir block count
 *
 * @return result
 */
result_t analize_count(const maps &map, const direct_count_t &count, const block_count_t &dir);

class processProf {
private:

    // using result_t = std::vector < std::tuple<
    // std::string, mem_range,
    // > >;

    std::unordered_map<pid_t, block_count_t > ans;
    // std::map<std::string, std::vector<mem_range> >
    maps file_map;

    std::map<pid_t, ip_t> lastcommand;

    std::unordered_map<ip_t, bool> need_singlestep;
    direct_count_t direct_count;
    std::map<pid_t, mem_range> cache_range_for_check;

    dumpCache cache;
protected:
    void stop_trace(const pid_t pid);
    void reflush_map(const pid_t pid);
    bool check_process(const pid_t pid);
    inline bool singleblock(const pid_t pid);
    inline bool singlestep(const pid_t pid);
    bool process_pause(const pid_t pid);
    bool process_start(const pid_t pid);

    bool ptrace_once(const pid_t pid);

    bool checkip(const ip_t ip, const pid_t pid);

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
    void trace(const pid_t pid, const int time, const int gap);

    void traceFull(const pid_t pid);

    result_t analize_count() const;

    processProf(const std::string &file): cache(file) {}
};


} // namespace ptraceProf
