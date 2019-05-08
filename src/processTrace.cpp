#include "processTrace.hpp"

#include <sys/types.h> // pid_t
#include <sys/reg.h> // RIP
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <dirent.h> // opendir
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <nlohmann/json.hpp> // json

namespace ptraceProf {


void ptraceThisProcess() {
    ptrace(PTRACE_TRACEME, getpid(), 0, 0);
}

ip_t get_ip(const pid_t pid) {
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
    lastcommand[pid] = 0;
    if(ptrace(PTRACE_ATTACH, pid, 0, 0)) {
        // std::cerr << "fail to attach pid :" << pid << '\t';
        // std::cerr << strerror(errno) << std::endl;;
        return check_process(pid);
    }
    int status;
    if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
        return check_process(pid);
    }
    return true;
}

bool processProf::process_start(const pid_t pid) {
    lastcommand[pid] = 0;
    if(ptrace(PTRACE_DETACH, pid, 0, 0)) {
        // std::cerr << "fail to detach pid :" << pid << '\t';
        // std::cerr << strerror(errno) << std::endl;;
        return check_process(pid);
    }
    return true;
}

bool start_with(const std::string &base, const std::string &head) {
    for(int i = 0; i < head.size(); ++i) {
        if(base[i] != head[i]) {
            return false;
        }
    }
    return true;
}

ip_t force_jump(const std::string &info) {
    if(info.size() == 0) {
        return 0;
    }
    if(start_with(info, "bnd ")) {
        return force_jump(info.substr(4));
    }
    std::vector<std::string> force_jump_list = {
        "callq", "jmpq", "retq", "syscall", "jmp ", "repz retq "
    };
    for(auto front : force_jump_list) {
        if(start_with(info, front)) {
            if(info.size() <= 7) {
                return -1;
            }
            ip_t adder = -1;
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

bool need_check(const std::string &info) {
    if(start_with(info, "rep ")) {
        return true;
    } else if(start_with(info, "repz ")) {
        return true;
    } else if(start_with(info, "repe ")) {
        return true;
    }
    return false;
}

ip_t may_jump(const std::string &info) {
    if(info.size() == 0) {
        return 0;
    }
    if(start_with(info, "bnd ")) {
        return may_jump(info.substr(4));
    }
    // const std::vector<std::string> may_jump_list = {
    // "jo", "jno", "jc", "jnc", "jz", "je", "jnz", "jne", "js", "jns",
    // "jp", "jpe", "jnp", "jpo", "jb", "jnae", "jnb", "jae", "jbe", "jna",
    // "jnbe", "ja", "jl", "jnge", "jnl", "jge", "jle", "jng", "jnle", "jg"
    // };
    if(info[0] != 'j') {
        return 0;
    } else {
        std::stringstream ss(info);
        std::string cmd;
        ip_t addre = 0;
        ss >> cmd >> std::hex >> addre;
        return addre;
    }
    // for(const std::string &front : may_jump_list) {
    // if(start_with(info, front)) {
    // std::stringstream ss(info.substr(front.size() + 1));
    // std::string s = ss.str();
    // ip_t addr = 0;
    // ss >> std::hex >> addr;
    // return addr;
    // }
    // }
}

std::string lltoString(long long t) {
    std::string result;
    std::stringstream ss;
    ss << " " << std::hex << t << " ";
    ss >> result;
    return result;
}

bool may_jump(const std::string &info, const ip_t next_addre) {
    auto add = lltoString(next_addre);
    return info.find(add) != std::string::npos;
}


void processProf::readCache(const std::string &file) {
    if(orderMap::file_exist(file)) {
        std::ifstream fs(file);
        nlohmann::json cache;
        this->singlestep_cache.clear();
        fs >> cache;
        for(auto it = cache.begin(); it != cache.end(); ++it) {
            for(auto i : it.value().get<std::vector<ip_t> >()) {
                this->singlestep_cache[it.key()].insert(i);
            }
        }
    }
}

void processProf::writeToCache(const std::string &file)const {
    std::ofstream fs(file);
    fs << nlohmann::json(this->singlestep_cache);
}

std::set<ip_t>processProf::update_singlestep_map(const std::map< unsigned int, std::tuple <
        order_t,
        std::string > > &block) {
    std::set<ip_t> ans;
    if(block.size()) {
        // 当前块的路径
        std::set<ip_t> has;
        // 条件跳转的出口
        std::set<ip_t> outs;
        for(auto [addre, _] : block) {
            auto [__, info] = _;
            has.insert(addre);
            ip_t out = 0;
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
                    // 清除块路径，避免重复标记
                    has.clear();
                } else {
                    outs.insert(out);
                }
            } else if(need_check(info)) {
                // 如果当前语句需要单步检查，标记队列中包括本句在内的所有语句
                for(auto point : has) {
                    ans.insert(point);
                }
                // 清除块路径，避免重复标记
                has.clear();
                ans.insert(addre);
            }
        }
    }
    return ans;
}

std::set<ip_t> processProf::update_singlestep_map(const std::string &file) {
    using ::ptraceProf::get_cmd_stream;
    std::cout << "updating " << file << std::endl;
    auto fs = get_cmd_stream("objdump -d " + file);
    std::set<ip_t>ans;
    while(fs) {
        auto need_siglestep  = update_singlestep_map(::ptraceProf::dumpReader::read_block(fs));
        ans.merge(need_siglestep);
    }
    return ans;
}

void processProf::stop_trace(const pid_t pid) {
    lastcommand.erase(pid);
}

void processProf::reflush_map(const pid_t pid) {
    using ::ptraceProf::mapsReader::readMaps;
    using ::ptraceProf::orderMap::getProcessCount;
    const auto new_file_map = readMaps(pid);
    for(const auto [file, ranges] : new_file_map) {
        if(!::ptraceProf::orderMap::file_exist(file)
                || file_map.find(file) != file_map.end()) {
            // 文件不存在或者文件已经处理过
            continue;
        }
        std::set<ip_t>list;
        if(auto it = this->singlestep_cache.find(file); it != singlestep_cache.end()) {
            // 如果在objdump缓存中找到了，使用缓存
            list = it->second;
        } else {
            // 如果没有找到，重新分析
            list = update_singlestep_map(file);
            for(const ip_t ip : list) {
                this->singlestep_cache[file].insert(ip);
            }
        }
        if(is_dynamic_file(file)) {
            for(const auto addre : list) {
                for(const auto range : ranges) {
                    if(addre > range.offset && addre - range.offset + range.start < range.end) {
                        need_singlestep[addre - range.offset + range.start] = true;
                    }
                }
            }
        } else {
            for(const auto addre : list) {
                need_singlestep[addre] = true;
            }
        }
    }
    file_map = new_file_map;
}

std::vector<pid_t> ListThreads(pid_t pid) {
    std::vector<pid_t> result;
    std::stringstream dirname;
    dirname << "/proc/" << pid << "/task";
    auto ls = get_cmd_stream("ls " + dirname.str());
    while(ls) {
        std::string line;
        if(std::getline(ls, line)) {
            result.push_back(std::stoi(line));
        } else {
            break;
        }

    }
    return result;
}

bool processProf::check_process(const pid_t pid) {
    // kill if unable trace
    // do nothing if no run
    // just let it crash
    kill(pid, 0);
}

bool processProf::ptrace_once(const pid_t pid) {
    if(lastcommand[pid] && !need_singlestep[lastcommand[pid]]) {
        if(this->singleblock(pid)) {
            auto ip = get_ip(pid);
            if(!checkip(ip, pid)) {
                return false;
            }
            if(lastcommand[pid]) {
                ++this->ans[pid][lastcommand[pid]][ip];
                auto [file, offset] = get_offset_and_file_by_ip(lastcommand[pid]);
                // std::cerr << "from " << file << " " << lltoString(offset) << '\t';
                // std::tie(file, offset) = get_offset_and_file_by_ip(ip);
                // std::cerr << " to " << file << " " << lltoString(offset) << std::endl;
            }
            lastcommand[pid] = ip;
            return true;
        } else {
            return false;
        }
    } else {
        if(lastcommand[pid]) {
            ++this->direct_count[lastcommand[pid]];
            // auto [file, offset] = get_offset_and_file_by_ip(lastcommand[pid]);
            // std::cerr << "count " << file << " " << lltoString(offset) << std::endl;
        }
        if(this->singlestep(pid)) {
            const auto ip = get_ip(pid);
            if(!checkip(ip, pid)) {
                return false;
            }
            lastcommand[pid] = ip;
            return true;
        } else {
            return false;
        }
    }
    return false;
}

void processProf::trace(const pid_t pid) {
    ptrace_once(pid);
    if(!this->process_start(pid)) {
        return;
    }
    while(true) {
        std::vector<std::thread> threads;
        const auto pids = ListThreads(pid);
        if(pids.empty()) {
            return;
        }
        for(const auto pid : pids) {
            threads.push_back(std::thread([pid, this]() {
                this->process_pause(pid);
                for(int i = 0; i < 10; ++i) {
                    if(!ptrace_once(pid)) {
                        return;
                    }
                }
                this->process_start(pid);
            }));
        }
        for(auto &thread : threads) {
            thread.join();
        }
    }
}

result_t processProf::analize_count() const {
    auto result = ptraceProf::analize_count(this->file_map, this->direct_count);
    for(const auto&[ip, dir] : ans) {
        for(auto [file, add_count_pair] : ptraceProf::analize_count(this->file_map, dir)) {
            for(auto [addre, count] : add_count_pair) {
                result[file][addre] += count;
            }
        }
    }
    return result;
}

bool processProf::checkip(const ip_t ip, const pid_t pid) {
    if(in_range(ip, this->cache_range_for_check[pid])) {
        return true;
    }
    for(const auto &[file, ranges] : file_map) {
        for(const auto range : ranges) {
            if(::ptraceProf::in_range(ip, range)) {
                cache_range_for_check[pid] = range;
                return true;
            }
        }
    }
    // std::cerr << "maps change" << std::endl;
    reflush_map(pid);
    // std::cerr << "maps read over" << std::endl;
    for(const auto &[file, ranges] : file_map) {
        for(const auto range : ranges) {
            if(::ptraceProf::in_range(ip, range)) {
                cache_range_for_check[pid] = range;
                return true;
            }
        }
    }
    return false;
}

bool is_dynamic_file(const std::string &file) {
    static std::map<std::string, bool> is_dynamic;
    auto it = is_dynamic.find(file);
    if(it == is_dynamic.end()) {
        auto fs = get_cmd_stream("file " + file);
        const std::string line = fs.str();
        is_dynamic[file] = line.find("dynamically linked") != std::string::npos;
        it = is_dynamic.find(file);
    }
    return it->second;
}

std::pair<std::string, ip_t> find_file_and_offset(const ::ptraceProf::mapsReader::result_t &file_map, const ip_t ip) {
    for(const auto &[file, ranges] : file_map) {
        for(const auto range : ranges) {
            if(::ptraceProf::in_range(ip, range)) {
                if(is_dynamic_file(file)) {
                    return std::make_pair(file, ip - range.start + range.offset);
                } else {
                    return std::make_pair(file, ip);
                }
            }
        }
    }
    return std::make_pair(std::string(), 0);
}

std::pair<direct_count_t, maps> dump_and_trace_sign(const pid_t pid) {
    int status = -1;
    wait(&status);
    maps map = ::ptraceProf::mapsReader::readMaps(pid);
    //{filename:{addre(hex),time}}
    direct_count_t result;
    result_t ans;
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
        const auto ip = get_ip(pid);
        ++result[ip];
        auto [file, offset] = find_file_and_offset(map, ip);
        if(file == "") {
            map = ::ptraceProf::mapsReader::readMaps(pid);
            // std::tie(file, offset) = find_file_and_offset(map, ip);
        }
        // ans[file][lltoString(offset)]++;

        // struct user_regs_struct regs;
        // ptrace(PTRACE_GETREGS,pid,nullptr,&regs);
        // std::cerr << lltoString(offset) << '\t' << file << '\n';
    }
    return std::make_pair(result, map);
}

result_t analize_count(const maps &map, const direct_count_t &count) {
    result_t result;
    for(const auto [ip, times] : count) {
        const auto[file, offset] = find_file_and_offset(map, ip);
        result[file][lltoString(offset)] = times;
    }
    return result;
}

result_t analize_count(const maps &map,
                       const direct_count_t &count,
                       const block_count_t &dir) {
    result_t result;
    result.merge(analize_count(map, count));
    result.merge(analize_count(map, dir));
    return result;
}

result_t analize_count(const maps &map,
                       const block_count_t &order_result) {
    std::map<std::string, std::map<ip_t, std::map<ip_t, count_t> > > result;
    for(const auto[start_ip, outs] : order_result) {
        const auto [start_file, start_offset] = find_file_and_offset(map, start_ip);
        for(const auto[end_ip, times] : outs) {
            const auto [end_file, end_offset] = find_file_and_offset(map, end_ip);
            if(start_file == end_file) {
                result[start_file][start_offset][end_offset] += times;
            } else {
                result[start_file][start_offset][-1] += times;
            }
        }
    }
    return analize_count(result);
}

result_t analize_count(
    const std::map<std::string, std::map<ip_t, std::map<ip_t, count_t> > > &ans) {
    result_t result;
    std::vector<std::thread> threads;
    for(const auto&[file, add_pair] : ans) {
        // TODO 线程数量检查
        threads.push_back(std::thread([&]() {
            auto obj_s = ::ptraceProf::get_cmd_stream("objdump -d " + file);
            auto block = ::ptraceProf::dumpReader::read_block(obj_s);
            std::cout << file << std::endl;
            for(const auto&[start_offset, end_time_pair] : add_pair) {
                while(block.find(start_offset) == block.end()) {
                    if(!obj_s) {
                        break;
                    }
                    block = ::ptraceProf::dumpReader::read_block(obj_s);
                }
                if(!block.size()) {
                    break;
                }

                for(const auto [end, times] : end_time_pair) {
                    bool start = false;
                    for(auto [addre, _] : block) {
                        if(!start) {
                            if(addre == start_offset) {
                                start = true;
                            } else {
                                continue;
                            }
                        }
                        if(no_run(std::get<1>(_))) {
                            continue;
                        }
                        result[file][lltoString(addre)] += times;
                        if(force_jump(std::get<1>(_))) {
                            break;
                        }
                        if(end != -1 && may_jump(std::get<1>(_), end)) {
                            break;
                        }
                    }
                }
            }
        }));
    }
    for(auto &thread : threads) {
        thread.join();
    }
    return result;
}
}
