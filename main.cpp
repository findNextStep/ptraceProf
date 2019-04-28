#include <iostream>
#include "orderMap.hpp"
#include "readDump.hpp"
#include "processTrace.hpp"
#include <nlohmann/json.hpp>
#include <sstream>
#include <time.h>

std::string lltoString(long long t) {
    std::string result;
    std::stringstream ss;
    ss << std::hex << t;
    ss >> result;
    return result;
}

auto _find_it(const ::ptraceProf::mapsReader::result_t &file_map, unsigned long long ip) {
    for(const auto &item : file_map) {
        for(const auto range : item.second) {
            if(::ptraceProf::processProf::in_range(ip, range)) {
                return std::make_pair(item.first, range);
            }
        }
    }
    return std::make_pair(std::string(), ::ptraceProf::mapsReader::mem_range());
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
        auto item = _find_it(maps, ip);
        if(item.first == "") {
            maps = ::ptraceProf::mapsReader::readMaps(pid);
            item = _find_it(maps, ip);
        }
        ans[item.first][lltoString(ip - item.second.start + item.second.offset)]++;

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
    for(auto item : pp.get_ans()) {
        auto it_start = find_it(pp.get_file_map(), item.first.first);
        auto it_end = find_it(pp.get_file_map(), item.first.second);
        if(it_start.first == it_end.first) {
            ans[it_start.first][item.first.first - it_start.second.start + it_start.second.offset]
            [item.first.second - it_end.second.start + it_end.second.offset] = item.second;
        } else {
            ans[it_start.first][item.first.first - it_start.second.start + it_start.second.offset][-1] +=
                item.second;
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
    if (start_with("bnd",info)){
        return force_jump(info.substr(4));
    }
    if(start_with(info, "call")) {
        return true;
    } else if(start_with(info, "jmpq")) {
        return true;
    } else if(start_with(info, "retq") || start_with(info, "repz")) {
        return true;
    } else if(start_with(info, "syscall")) {
        return true;
    }
    return false;
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


auto analize(const std::map<std::string, std::map<int, std::map<int, int> > > ans,std::map<std::string, std::map<std::string, int> > result = {}) {
    // std::map<std::string, std::map<int, std::map<int, int> > > ans = js;
    for(auto [file, add_pair] : ans) {
        if(file == "/home/pxq/final_design/ptrace_prof/a.out") {
            continue;
        }
        auto obj_s = ::ptraceProf::get_cmd_stream("objdump -d " + file);
        auto block = ::ptraceProf::dumpReader::read_block(obj_s);
        std::cout << file << std::endl;
        for(auto [addr, end_time_pair] : add_pair) {
            while(!add_in_block(addr, block)) {
                if(!obj_s) {
                    break;
                }
                block = ::ptraceProf::dumpReader::read_block(obj_s);
            }
            if(!block.size()) {
                break;
            }

            for(auto [end, times] : end_time_pair) {
                bool start = false;
                for(auto [addre, _] : block) {
                    if(!start) {
                        if(addre == addr) {
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
    }
    return ::nlohmann::json(result);
}

int main() {
    int child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, 0);
        // execl("/bin/ls", "ls");
        execl("./a.out", "out");
    } else {
        printf("%d\n", child);
        // some_time_trace(child);
        // std::cerr << dump_and_trace_sign(child).dump(4);
        ::ptraceProf::processProf pp;
        pp.trace(child);
        std::cerr << analize(analize_trace(pp)).dump(4);
    }
    return 0;
}


