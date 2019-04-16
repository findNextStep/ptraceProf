#include "mapsReader.hpp"
#include <iostream>
#include <fstream>
#include <string>
#include <chrono>

template<typename T>
auto count_time(T func) {
    auto start = ::std::chrono::system_clock::now();
    func();
    auto end = ::std::chrono::system_clock::now();
    auto duration = end - start;
    return duration.count();
}

int main() {
    using namespace ptraceProf::mapsReader;
    using namespace std;
    std::cout << count_time([]() {
        for(auto file : readMaps()) {
        cout << file.first << endl;
        }
    });
}
