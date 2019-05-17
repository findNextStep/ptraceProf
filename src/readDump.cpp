#include "readDump.hpp"
#include "processTrace.hpp"
#include <queue>
#include <thread>
#include <mutex>


namespace ptraceProf {
namespace dumpReader {

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

std::pair<std::set<ip_t>, std::set<ip_t> > get_single_step_list(const result_t &block) {
    std::set<ip_t> ans, has, outs, all;
    for(const auto&[addre, _] : block) {
        all.insert(addre);
        const auto &[order, info] = _;
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
    return std::make_pair(ans, all);
}

std::pair<std::set<ip_t>, std::set<ip_t> > get_single_step_list(const std::string &file) {
    using ::ptraceProf::get_cmd_stream;
    auto fs = get_cmd_stream("objdump -d " + file);
    std::pair<std::set<ip_t>, std::set<ip_t> >ans;
    std::vector<std::thread> threads;
    std::mutex deal_queue_lock;
    std::queue<dumpReader::result_t> deal_queue;
    std::mutex ans_queue_mutex;
    std::queue<std::pair<std::set<ip_t>, std::set<ip_t> > > ans_queue;
    bool no_finish = true;
    int count = 0;
    auto deal_func = [&] {
        ++count;
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
            auto ans_tmp = get_single_step_list(block);
            ans_queue_mutex.lock();
            ans_queue.push(ans_tmp);
            ans_queue_mutex.unlock();
        }
        --count;
    };
    // it seems max in nowhere
    int max_threads = [](auto a, auto b) {
        return a > b ? a : b;
    }
    (std::thread::hardware_concurrency() - 1, 1);
    for(int i = 0; i < max_threads; ++i) {
        threads.push_back(std::thread(deal_func));
    }
    while(fs) {
        deal_queue.push(::ptraceProf::dumpReader::read_block(fs));
    }
    no_finish = false;
    while(count) {
        if(!ans_queue.empty()) {
            for(auto i : ans_queue.front().first) {
                ans.first.insert(i);
            }
            for(auto i : ans_queue.front().second) {
                ans.second.insert(i);
            }
            ans_queue.pop();
        }
    }
    for(auto &thrad : threads) {
        thrad.join();
    }

    while(!ans_queue.empty()) {
        for(auto i : ans_queue.front().first) {
            ans.first.insert(i);
        }
        for(auto i : ans_queue.front().second) {
            ans.second.insert(i);
        }
        ans_queue.pop();
    }
    return ans;
}

} // DumpReader
} // ptraceProf
