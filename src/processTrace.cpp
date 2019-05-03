#include <processTrace.hpp>

namespace ptraceProf {

bool processProf::start_with(const std::string &base, const std::string &head) {
    for(int i = 0; i < head.size(); ++i) {
        if(base[i] != head[i]) {
            return false;
        }
    }
    return true;
}

int processProf::force_jump(const std::string &info) {
    if(info.size() == 0) {
        return 0;
    }
    if(start_with(info, "bnd ")) {
        return force_jump(info.substr(4));
    }
    std::vector<std::string> force_jump_list = {
        "callq", "jmpq", "retq", "repz", "syscall"
    };
    for(auto front : force_jump_list) {
        if(start_with(info, front)) {
            if(info.size() <= 7) {
                return -1;
            }
            int adder = -1;
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


unsigned int processProf::may_jump(const std::string &info) {
    if(info.size() == 0) {
        return 0;
    }
    if(start_with(info, "bnd ")) {
        return may_jump(info.substr(4));
    }
    const std::vector<std::string> may_jump_list = {
        "jo", "jno", "jc", "jnc", "jz", "je", "jnz", "jne", "js", "jns",
        "jp", "jpe", "jnp", "jpo", "jb", "jnae", "jnb", "jae", "jbe", "jna",
        "jnbe", "ja", "jl", "jnge", "jnl", "jge", "jle", "jng", "jnle", "jg"
    };
    if(info[0] != 'j') {
        return 0;
    }
    for(const std::string &front : may_jump_list) {
        if(start_with(info, front)) {
            std::stringstream ss(info.substr(front.size() + 1));
            std::string s = ss.str();
            unsigned int addr = 0;
            ss >> std::hex >> addr;
            return addr;
        }
    }
    return 0;
}

std::string processProf::lltoString(long long t) {
    std::string result;
    std::stringstream ss;
    ss << " " << std::hex << t << " ";
    ss >> result;
    return result;
}

bool processProf::may_jump(const std::string &info, const unsigned long long next_addre) {
    auto add = lltoString(next_addre);
    return info.find(add) != std::string::npos;
}

std::set<unsigned int>processProf::update_singlestep_map(const std::map< unsigned int, std::tuple <
        std::vector<unsigned short>,
        std::string > > &block) {
    std::set<unsigned int> ans;
    if(block.size()) {
        unsigned int block_start = block.begin()->first;
        // 当前块的路径
        std::set<unsigned int> has;
        // 条件跳转的出口
        std::set<unsigned int> outs;
        for(auto [addre, _] : block) {
            // std::cout << std::hex << addre << std::endl;
            auto [__, info] = _;
            has.insert(addre);
            unsigned int out = 0;
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
                } else {
                    outs.insert(out);
                }
            }
        }
    }
    return ans;
}

std::set<unsigned int> processProf::update_singlestep_map(const std::string &file) {
    using ::ptraceProf::get_cmd_stream;
    auto fs = get_cmd_stream("objdump -d " + file);
    std::set<unsigned int>ans;
    while(fs) {
        auto need_siglestep  = update_singlestep_map(::ptraceProf::dumpReader::read_block(fs));
        ans.merge(need_siglestep);
    }
    return ans;
}

void processProf::stop_trace(const pid_t pid) {
    pid_order.erase(pid);
    lastcommand.erase(pid);
    range_cache.erase(pid);
}

void processProf::reflush_map(const pid_t pid) {
    using ::ptraceProf::mapsReader::readMaps;
    using ::ptraceProf::orderMap::getProcessCount;
    file_map = readMaps(pid);
    for(auto &order : this->pid_order) {
        getProcessCount(pid, order.second);
    }
    for(auto &[pid, cache] : range_cache) {
        cache = pid_order[pid].end();
    }
    this->need_singlestep.clear();
    for(auto [file, ranges] : file_map) {
        if(!::ptraceProf::orderMap::file_exist(file)) {
            continue;
        }
        auto list = update_singlestep_map(file);
        for(auto addre : list) {
            for(auto range : ranges) {
                if(addre > range.offset && addre - range.offset + range.start < range.end) {
                    need_singlestep[addre - range.offset + range.start] = true;
                }
            }
        }
    }
}

std::vector<pid_t> processProf::ListThreads(pid_t pid) {
    std::vector<pid_t> result;
    std::stringstream dirname;
    dirname << "/proc/" << pid << "/task";
    auto *dir = opendir(dirname.str().c_str());
    if(dir == nullptr) {
        // fail
        return {};
    }
    dirent *entry;
    while((entry = readdir(dir)) != nullptr) {
        std::string name = entry->d_name;
        if(name[0] != '.') {
            result.push_back(static_cast<pid_t>(std::stoi(name)));
        }
    }
    return result;
}

bool processProf::check_process(const pid_t pid) {
    if(kill(pid, 0)) {
        // process not run
        // https://stackoverflow.com/questions/11785936/how-to-find-if-a-process-is-running-in-c
        // process never run ,stop trace and save ans
        return false;
    }
    // error catch
    // it shouldn`t happen
    fprintf(stderr, "the pid : %d can not trace but can kill\nIt shouldn`t happened\n", pid);
    exit(1);
    return true;
}

bool processProf::ptrace_once(const pid_t pid) {
    if(this->singleblock(pid)) {
        auto ip = get_ip(pid);
        auto [file, offset] = get_offset_and_file_by_ip(ip);
        std::cerr << "noral " << file << "\t" << lltoString(offset) << '\n';
        // else {
        // no hit cache
        auto it = find_range(pid, ip);
        if(it == pid_order[pid].end()) {
            // if no found rip in maps reload maps and try again
            // TODO 增量式maps读取
            this->reflush_map(pid);
            it = find_range(pid, ip);
            // TODO error detect
        }
        if(lastcommand[pid]) {
            std::cerr << "setin ";
            std::tie(file, offset) = get_offset_and_file_by_ip(lastcommand[pid]);
            std::cerr << file << "\t" << lltoString(offset) << "\tto ";
            std::tie(file, offset) = get_offset_and_file_by_ip(ip);
            std::cerr << file << "\t" << lltoString(offset) << '\n';
            this->ans[pid][lastcommand[pid]][ip] ++;
        }
        lastcommand[pid] = ip;
        if(this->need_singlestep[ip]) {
            this->direct_count[ip] += 1;
            do {
                if(this->singlestep(pid)) {
                    ip = get_ip(pid);
                    std::tie(file, offset) = get_offset_and_file_by_ip(ip);
                    std::cerr << "insin " << file << "\t" << lltoString(offset) << std::endl;
                    this->direct_count[ip] += 1;
                } else {
                    return false;
                }
            } while(this->need_singlestep[ip]);
            lastcommand[pid] = get_ip(pid);
            std::tie(file, offset) = get_offset_and_file_by_ip(ip);
            std::cerr << "outsi " << file << "\t" << lltoString(offset) << std::endl;
            this->direct_count[ip] -= 1;
            return true;
        }
        return true;
    }
    return false;
}


}