#include "readDump.hpp"
#include "typedef.hpp"
#include "pipe.hpp"
#include <iostream>
#include <algorithm>
using namespace ptraceProf;
auto read_n_line(std::istream &a) {
    std::string s;
    int sum = 0;
    while(a) {
        std::getline(a, s);
        sum++;
    }
    std::cout << "has line " << sum << std::endl;
}
auto read_n_line(std::istream &&a) {
    if(a) {
        return read_n_line(a);
    }
}

std::string lltoString(long long t) {
    std::string result;
    std::stringstream ss;
    ss << " " << std::hex << t << " ";
    ss >> result;
    return result;
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
            ip_t addr = 0;
            ss >> std::hex >> addr;
            return addr;
        }
    }
    return 0;
}

int main(int argc, char **argv) {
    using ::ptraceProf::get_cmd_stream;
    // using ::ptraceProf::get_cmd_stream_;
    using ::ptraceProf::dumpReader::read_objdump;
    using std::cout;
    using std::endl;
    ::ptraceProf::dumpReader::result_t ans;;
    if(argc < 2) {
        ans = read_objdump(get_cmd_stream(std::string("objdump -d ") + argv[1]));
    } else {
        ans = read_objdump(get_cmd_stream("objdump -d ./a.out"));
    }
    if(argc < 3) {
        for(auto [add, pair] : ans) {
            cout << lltoString(add);
            auto[a, info] = pair;
            cout << "\t" << info ;
            ip_t i;
            if((i = force_jump(info)) == 0) {
                cout << "\tforce";
            }
            if((i = may_jump(info)) != 0) {
                cout << "\t" << "may jump " << lltoString(i);
            }
            if(need_check(info)) {
                cout << "\tneed check";
            }
            cout << endl;
        }
    } else {
        std::stringstream ss(argv[2]);
        int add;
        ss >> std::hex >> add;
        auto [_, info] = ans[add];
        ip_t i;
        cout << info;
        if((i = force_jump(info)) != 0) {
            cout << "\tforce ";
            if (i != -1){
                cout << lltoString(i);
            }
        }
        if((i = may_jump(info)) != 0) {
            cout << "\t" << "may jump " << lltoString(i);
        }
        if(need_check(info)) {
            cout << "\tneed check";
        }
        cout << endl;
    }
}
