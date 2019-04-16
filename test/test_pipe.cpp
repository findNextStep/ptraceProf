#include "pipe.hpp"
#include <string>
#include <vector>

int main() {
    using ::ptraceProf::get_cmd_stream;
    std::vector<std::string> cmd = {
        // "/bin/echo", "233"
        "/bin/ls","/home/pxq"
    };
    auto fs = get_cmd_stream({
        // "/bin/echo", "233"
        "/bin/ls","/home/pxq"
    });

    while(!fs.eof() && fs.is_open()) {
        std::string line;
        std::getline(fs,line);
        std::cout <<"line "<< line << std::endl;
    }
    fs.close();
}
