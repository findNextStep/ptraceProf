#include "readDump.hpp"
#include "processTrace.hpp"
#include <queue>
#include <thread>
#include <mutex>


namespace ptraceProf {
namespace dumpReader {


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
    std::set<std::string> force_jump_list = {
        "callq", "jmpq", "retq", "syscall", "jmp", "repz retq"
    };
    ip_t addre = -1;
    std::string command = "";
    std::stringstream ss(info);
    ss >> command >> std::hex >> addre;
    if(force_jump_list.find(command) != force_jump_list.end()) {
        if(addre == 0) {
            return -1;
        }
        return addre;
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
order_t get_order(std::istream &&ss) {
    short i;
    order_t result;
    result.reserve(8);
    while(ss >> std::hex >> i) {
        result.push_back(i);
    }
    return result;
}


order_map deal_line_order(const std::string &line) {
    if(line == "") {
        return order_map{(ip_t) -1};
    }
    std::string::size_type mid, end;
    mid = line.find('\t');
    end = line.find('\t', mid + 1);
    if(mid == std::string::npos) {
        return order_map{(ip_t) -1};
    }
    ++mid;
    ip_t i = -1;
    std::stringstream ss(line);
    ss >> std::hex >> i;
    if(end != line.npos) {
        return {i, line.substr(mid, end - mid), line.substr(end + 1)};
    } else {
        return{i, line.substr(mid), ""};
    }
}

std::string try_read_header(const std::string &line) {
    unsigned int addr = -1;
    std::stringstream ss(line);
    ss >> std::hex >> addr;
    std::string func;
    if(std::getline(ss, func)) {
        return std::string(func.substr(2, func.size() - 4));
    } else {
        return std::string("");
    }
}

result_t read_block(pipstream &is) {
    std::string line;
    std::getline(is, line);
    std::string func_name = try_read_header(line);
    result_t result;
    while(func_name.size() &&
            std::getline(is, line) &&
            line.size()) {
        auto order = deal_line_order(line);
        result[order.address] = std::make_tuple(order.order, order.info);
    }
    return result;
}

std::pair<std::string, result_t> read_block_with_func_name(pipstream &is) {
    std::string line;
    std::getline(is, line);
    std::string func_name = try_read_header(line);
    result_t result;
    while(func_name.size()) {
        std::string line;
        if(!std::getline(is, line)) {
            break;
        }
        auto order = deal_line_order(line);
        if(order.address == -1) {
            break;
        }
        result[order.address] = std::make_tuple(order.order, order.info);
    }
    return std::make_pair(func_name, result);
}

result_t read_objdump(pipstream &is) {
    result_t result;
    while(is) {
        auto block = read_block(is);
        for(const auto &item : block) {
            result.emplace(item);
        }
    }
    return result;
}
result_t read_objdump(pipstream &&is) {
    return read_objdump(is);
}

std::set<ip_t> get_single_step_list(const result_t &block) {
    std::set<ip_t> ans, has;
    for(const auto&[addre, _] : block) {
        const auto &[order, info] = _;
        std::set<ip_t> outs;
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
    return ans;
}

std::set<ip_t> get_single_step_list(const std::string &file) {
    using ::ptraceProf::get_cmd_stream;
    std::cout << "updating " << file << std::endl;
    auto fs = get_cmd_stream("objdump -d " + file);
    std::set<ip_t>ans;
    std::vector<std::thread> threads;
    std::mutex deal_queue_lock;
    std::queue<dumpReader::result_t> deal_queue;
    bool no_finish = true;
    auto deal_func = [&] {
        while(no_finish || !deal_queue.empty()) {
            deal_queue_lock.lock();
            while(no_finish && deal_queue.empty()) {}
            if(deal_queue.empty()) {
                deal_queue_lock.unlock();
                break;
            }
            const auto block = deal_queue.front();
            deal_queue.pop();
            deal_queue_lock.unlock();
            ans.merge(get_single_step_list(block));

        }
    };
    for(int i = 0; i < std::thread::hardware_concurrency() - 1; ++i) {
        threads.push_back(std::thread(deal_func));
    }
    while(fs) {
        deal_queue.push(::ptraceProf::dumpReader::read_block(fs));
    }
    no_finish = false;
    deal_func();
    for(auto &thrad : threads) {
        thrad.join();
    }
    std::cout << "updating " << file << " over" << std::endl;
    return ans;
}

} // DumpReader
} // ptraceProf
