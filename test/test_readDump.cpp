#include "readDump.hpp"
#include "pipe.hpp"
#include <iostream>
#include <algorithm>
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

int main() {
    using ::ptraceProf::get_cmd_stream;
    // using ::ptraceProf::get_cmd_stream_;
    using ::ptraceProf::dumpReader::read_objdump;
    using std::cout;
    using std::endl;
    // read_n_line(get_cmd_stream_({"/bin/echo","echo 233"}));

    // read_n_line(get_cmd_stream("objdump -d /home/pxq/final_design/ptrace_prof/a.out"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libc-2.27.so"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libgcc_s.so.1"));
    // read_n_line(get_cmd_stream("objdump -d /home/pxq/final_design/ptrace_prof/a.out"));
    // read_n_line(get_cmd_stream("objdump -d /home/pxq/final_design/ptrace_prof/a.out"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libc-2.27.so"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libgcc_s.so.1"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so"));
    // read_n_line(get_cmd_stream("objdump -d /usr/lib/x86_64-linux-gnu/libstdc++.so.6"));
    read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so"));
    cout << endl;
    read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so"));
    cout << endl;
    // return 0;
    cout << "size " <<read_objdump(get_cmd_stream("objdump -d /home/pxq/final_design/ptrace_prof/a.out")).size() << endl;
    cout << endl;
    read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libgcc_s.so.1"));
    // read_n_line(get_cmd_stream("objdump -d /home/pxq/final_design/ptrace_prof/a.out"));
    // read_n_line(get_cmd_stream("objdump -d /home/pxq/final_design/ptrace_prof/a.out"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libc-2.27.so"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libgcc_s.so.1"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so"));
    // read_n_line(get_cmd_stream("objdump -d /usr/lib/x86_64-linux-gnu/libstdc++.so.6"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so"));
    // read_n_line(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so"));
    // return 0;
    cout << read_objdump(get_cmd_stream("objdump -d /home/pxq/final_design/ptrace_prof/a.out")).size() << endl;
    cout << read_objdump(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libc-2.27.so")).size() << endl;
    cout << read_objdump(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libgcc_s.so.1")).size() << endl;
    cout << read_objdump(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so")).size() << endl;
    cout << read_objdump(get_cmd_stream("objdump -d /usr/lib/x86_64-linux-gnu/libstdc++.so.6")).size() << endl;
    cout << read_objdump(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so")).size() << endl;
    cout << read_objdump(get_cmd_stream("objdump -d /lib/x86_64-linux-gnu/libm-2.27.so")).size() << endl;
}
