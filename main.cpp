#include <iostream>
#include "orderMap.hpp"
#include "readDump.hpp"
#include "processTrace.hpp"
#include <nlohmann/json.hpp>
#include <sstream>
#include <time.h>
#include <sys/user.h>
#include <thread>

std::string lltoString(long long t) {
    std::string result;
    std::stringstream ss;
    ss << std::hex << t;
    ss >> result;
    return result;
}

std::pair<std::string, unsigned long long> _find_it(const ::ptraceProf::mapsReader::result_t &file_map, unsigned long long ip) {
    for(const auto &[file, ranges] : file_map) {
        for(const auto range : ranges) {
            if(::ptraceProf::processProf::in_range(ip, range)) {
                return std::make_pair(file, ip - range.start + range.offset);
            }
        }
    }
    return std::make_pair(std::string(), 0);
}

auto dump_and_trace_sign(const int pid) {
    int status = -1;
    wait(&status);
    auto maps = ::ptraceProf::mapsReader::readMaps(pid);
    //{filename:{addre(hex),time}}
    std::map<std::string, std::map<std::string, int> > ans;
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
        long ip = ptrace(PTRACE_PEEKUSER, pid, 8 * RIP, NULL);
        auto [file, offset] = _find_it(maps, ip);
        if(file == "") {
            maps = ::ptraceProf::mapsReader::readMaps(pid);
            std::tie(file, offset) = _find_it(maps, ip);
        }
        ans[file][lltoString(offset)]++;

        // struct user_regs_struct regs;
        // ptrace(PTRACE_GETREGS,pid,nullptr,&regs);
        std::cerr << lltoString(offset) << '\t' << file << '\n';
    }
    return nlohmann::json(ans);
}

auto analize_trace(const ::ptraceProf::orderMap::result_t &result) {
    auto &cout = std::cerr;
    using std::endl;
    std::string last_file = "";
    for(const auto &item : result) {
        if(last_file != std::get<0>(item)) {
            last_file = std::get<0>(item);
            cout << last_file << " :\n";
        }
        auto start = std::get<1>(item).start;
        const auto &li = std::get<2>(item);
        for(auto i = 0; i < li.size(); ++i) {
            for(auto jmp : li[i]) {
                cout << std::hex << i << " --> " << jmp.first << " : " << std::dec << jmp.second << endl;
            }
        }
    }
}

auto find_it(const ::ptraceProf::mapsReader::result_t &file_map, unsigned long long ip) {
    for(const auto &item : file_map) {
        for(const auto range : item.second) {
            if(::ptraceProf::processProf::in_range(ip, range)) {
                return std::make_pair(item.first, range);
            }
        }
    }
    std::cerr << "errror " << std::endl;
    exit(1);
}

auto analize_trace(const ::ptraceProf::processProf &pp) {
    auto &cout = std::cerr;
    using std::endl;
    // {file : {start_ip : {end_ip,time}}}
    std::map<std::string, std::map<int, std::map<int, int> > > ans;
    for(const auto [ip_pair, times] : pp.get_ans()) {
        const auto [start_ip, end_ip] = ip_pair;
        const auto [start_file, start_offset] = pp.get_offset_and_file_by_ip(start_ip);
        const auto [end_file, end_offset] = pp.get_offset_and_file_by_ip(end_ip);
        if(start_file == end_file) {
            ans[start_file][start_offset][end_offset] += times;
        } else {
            ans[start_file][start_offset][-1] += times;
        }
    }
    return ans;
}

bool start_with(const std::string &base, const std::string &head) {
    for(int i = 0; i < head.size(); ++i) {
        if(base[i] != head[i]) {
            return false;
        }
    }
    return true;
}

bool force_jump(const std::string &info) {
    return ::ptraceProf::processProf::force_jump(info) != 0;
}

bool may_jump(const std::string &info, const unsigned long long next_addre) {
    auto add = lltoString(next_addre);
    return info.find(add) != std::string::npos;
}

bool add_in_block(const int add, const std::map< unsigned int, std::tuple < std::vector<unsigned short>, std::string > > &result) {
    return result.find(add) != result.end();
}

bool no_run(const std::string &info) {
    return !info.size();
}


auto analize(const std::map<std::string, std::map<int, std::map<int, int> > > &ans,
std::map<std::string, std::map<std::string, int> > result = {}) {
    // std::map<std::string, std::map<int, std::map<int, int> > > ans = js;
    std::vector<std::thread> threads;
    for(const auto&[file, add_pair] : ans) {
        // TODO 线程数量检查
        threads.push_back(std::thread([&]() {
            auto obj_s = ::ptraceProf::get_cmd_stream("objdump -d " + file);
            auto block = ::ptraceProf::dumpReader::read_block(obj_s);
            std::cout << file << std::endl;
            for(const auto&[start_offset, end_time_pair] : add_pair) {
                while(!add_in_block(start_offset, block)) {
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
    return ::nlohmann::json(result);
}

int main(int argc, char **argv) {
    int child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // execl("/bin/ls", "ls");
        execl("./a.out", "out");
    } else {
        std::cout << "child == " << child << std::endl;
        if(argc == 2) {
            std::ofstream out("./test.sign.json");
            out << dump_and_trace_sign(child).dump(4);
            out.close();
        } else {
            std::ofstream outb("./test.bolck.json");
            ::ptraceProf::processProf pp;
            pp.trace(child);
            outb << analize(analize_trace(pp), pp.get_direct_count()).dump(4);
            outb.close();
        }
    }
    return 0;
}


