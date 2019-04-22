#include "readDump.hpp"
#include "pipe.hpp"
#include <iostream>
#include <algorithm>
int main() {
    using ::ptraceProf::get_cmd_stream;
    using ::ptraceProf::dumpReader::read_objdump;
    using std::cout;
    using std::endl;
    std::vector< std::pair<unsigned int, std::tuple <
    std::vector<unsigned short>,
        std::string > > > result;

    for(auto item :
            read_objdump(get_cmd_stream({"/usr/bin/objdump", "-d", "/bin/ls"}))) {
        result.push_back(item);
    }

    std::sort(result.begin(), result.end(), [](auto a, auto b) {
        return a.first < b.first;
    });

    for(auto item : result) {
        cout << std::hex << item.first << "\t: ";
        auto [order, info] = item.second;
        for(auto o : order) {
            cout << o << " ";
        }
        cout << '\t' << info << endl;
    }
}
