#include "processTrace.hpp"
#include "readDump.hpp"

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
#include <sys/stat.h>

#include <thread>

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
        check_process(pid);
        return false;
    }
    return true;
}

bool processProf::singlestep(const pid_t pid) {
    int status = 0;
    ptrace(PTRACE_SINGLESTEP, pid, 0, 0);
    if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
        check_process(pid);
        return false;
    }
    return true;
}

bool processProf::process_pause(const pid_t pid) {
    lastcommand[pid] = 0;
    if(ptrace(PTRACE_ATTACH, pid, 0, 0)) {
        // std::cerr << "fail to attach pid :" << pid << '\t';
        // std::cerr << strerror(errno) << std::endl;;
        check_process(pid);
        return false;
    }
    int status;
    if(waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) {
        check_process(pid);
        return false;
    }
    return true;
}

bool processProf::process_start(const pid_t pid) {
    lastcommand[pid] = 0;
    if(ptrace(PTRACE_DETACH, pid, 0, 0)) {
        // std::cerr << "fail to detach pid :" << pid << '\t';
        // std::cerr << strerror(errno) << std::endl;;
        check_process(pid);
        return false;
    }
    return true;
}

void processProf::stop_trace(const pid_t pid) {
    lastcommand.erase(pid);
}

void processProf::reflush_map(const pid_t pid) {
    using ::ptraceProf::mapsReader::readMaps;
    using ::ptraceProf::orderMap::getProcessCount;
    const auto new_file_map = readMaps(pid);
    bool is_launch = !tasklist.empty();
    bool need_launch = false;
    for(const auto[file, ranges] : new_file_map) {
        if(::ptraceProf::orderMap::file_exist(file)
                && file_map.find(file) == file_map.end()) {
            // 文件存在且未被处理过
            this->tasklist.push(file);
            file_map[file] = ranges;
            if(!is_launch) {
                need_launch = true;
            }
        }
    }
    if(need_launch) {
        std::thread thread([this]() {
            while(tasklist.size()) {
                const std::string file = tasklist.front();
                const auto ranges = file_map[file];
                std::set<ip_t> signle = cache.get_signle_step(file);
                std::set<ip_t> addres = cache.get_full_dump(file);
                if(is_dynamic_file(file)) {
                    for(const auto addre : addres) {
                        if(signle.find(addre) == signle.end()) {
                            for(const auto range : ranges) {
                                if(addre > range.offset && addre - range.offset + range.start < range.end) {
                                    noneed_singlestep[addre - range.offset + range.start] = true;
                                }
                            }
                        }
                    }
                } else {
                    for(const auto addre : addres) {
                        if(signle.find(addre) == signle.end()) {
                            noneed_singlestep[addre] = true;
                        }
                    }
                }
                tasklist.pop();
            }
        });
        thread.detach();
    }
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
    return kill(pid, 0);
}

bool processProf::ptrace_once(const pid_t pid) {
    if(lastcommand[pid] && noneed_singlestep[lastcommand[pid]]) {
        if(this->singleblock(pid)) {
            auto ip = get_ip(pid);
            if(lastcommand[pid]) {
                ++this->ans[pid][lastcommand[pid]][ip];
                // auto [file, offset] = get_offset_and_file_by_ip(lastcommand[pid]);
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
            lastcommand[pid] = ip;
            return true;
        } else {
            return false;
        }
    }
    return false;
}

void processProf::traceFull(const pid_t pid) {
    while(ptrace_once(pid)) {}
    return;
}

void processProf::trace(const pid_t pid, const int times, const int gap) {
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
            reflush_map(pid);
            threads.push_back(std::thread([pid, times, this]() {
                this->process_pause(pid);
                for(int i = 0; i < times; ++i) {
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
        if(gap != 0) {
            std::this_thread::sleep_for(std::chrono::nanoseconds(gap));
        }
    }
}

result_t processProf::analize_count() const {
    auto result = ptraceProf::analize_count(this->file_map, this->direct_count);
    for(const auto&[ip, dir] : ans) {
        auto test = ptraceProf::analize_count(this->file_map, dir);
        for(auto [file, add_count_pair] : test) {
            for(auto [addre, count] : add_count_pair) {
                result[file][addre] += count;
            }
        }
    }
    return result;
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
    for(const auto &pair : ans) {
        std::string file;
        std::map<ip_t, std::map<ip_t, count_t> > add_pair;
        // fix clang bug see
        // https://stackoverflow.com/questions/46114214/lambda-implicit-capture-fails-with-variable-declared-from-structured-binding
        std::tie(file, add_pair) = pair;
        // TODO 线程数量检查
        threads.push_back(std::thread([file, add_pair, &result] {
            auto obj_s = ::ptraceProf::get_cmd_stream("objdump -d " + file);
            while(obj_s) {
                auto block = ::ptraceProf::dumpReader::read_block(obj_s);
                count_t time = 0;
                std::map<ip_t, count_t> outs;
                for(const auto&[addre, _] : block) {
                    const auto&[order, info] = _;
                    if(time && !no_run(info)) {
                        result[file][lltoString(addre)] += time;
                    }
                    if(const auto it = add_pair.find(addre); it != add_pair.end()) {
                        for(const auto&[end, times] : it->second) {
                            time += times;
                            outs[end] += times;
                            result[file][lltoString(addre)] += times;
                        }
                    }
                    if(const auto addred = force_jump(info); addred) {
                        time = 0;
                        outs.clear();
                    } else if(const auto addred = may_jump(info); addred != 0) {
                        time -= outs[addred];
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
