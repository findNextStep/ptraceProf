#include "pipe.hpp"
#include <string>
#include <vector>

int main() {
    using ::ptraceProf::get_cmd_stream;
    auto fs = get_cmd_stream("echo 233");

    while(fs) {
        std::string line;
        std::getline(fs,line);
        std::cout <<"line "<< line << std::endl;
    }
}
