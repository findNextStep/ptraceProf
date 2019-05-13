#include "readDump.hpp"
#include "typedef.hpp"
#include "pipe.hpp"
#include <iostream>
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
