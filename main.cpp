#include <iostream>
#include "orderMap.hpp"
#include "processTrace.hpp"
#include <nlohmann/json.hpp>
#include <sstream>

std::string lltoString(long long t)
{
    std::string result;
    std::stringstream ss;
    ss <<std::hex << t;
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
    return std::make_pair(std::string(),::ptraceProf::mapsReader::mem_range());
}

auto dump_and_trace_sign(const int pid) {
    int status = -1;
    wait(&status);
    auto maps = ::ptraceProf::mapsReader::readMaps(pid);
    std::map<std::string,std::map<std::string,int> > ans;
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
        auto item = _find_it(maps,ip);
        if (item.first == ""){
            maps = ::ptraceProf::mapsReader::readMaps(pid);
            item = _find_it(maps,ip);
        }
        ans[item.first][lltoString(ip - item.second.start + item.second.offset)]++;

    }
    return nlohmann::json(ans);
}

auto analize_trace(const ::ptraceProf::orderMap::result_t &result) {
    auto &cout = std::cerr;
    cout << "start analize" << std::endl;
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
    cout << "start analize" << std::endl;
    using std::endl;
    for(auto item : pp.get_ans()) {
        auto it_start = find_it(pp.get_file_map(), item.first.first);
        auto it_end = find_it(pp.get_file_map(), item.first.second);
        // fprintf (stderr,"%lx --%d--> %lx\n",item.first.first,item.second,item.first.second);
        cout << std::hex << item.first.first - it_start.second.start + it_start.second.offset << " " << it_start.first << " "
             << std::hex << item.first.second - it_end.second.start + it_end.second.offset << " " << it_end.first << " "
             << std::dec << item.second << " "
             << "\n";
    }
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
        std::cerr << dump_and_trace_sign(child).dump(4);
        // ::ptraceProf::processProf pp;
        // pp.trace(child);
        // analize_trace(pp);
    }
}


