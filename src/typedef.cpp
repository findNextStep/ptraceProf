#include "typedef.hpp"
#include <iomanip>
#include <set>
namespace ptraceProf {
bool start_with(const std::string &base, const std::string &head) {
    for(unsigned int i = 0; i < head.size(); ++i) {
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

}