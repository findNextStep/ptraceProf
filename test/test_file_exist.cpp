#include "orderMap.hpp"
#include <iostream>
using ::ptraceProf::orderMap::file_exist;

int main(int argc,char **argv){
    if (argc == 1){
        std::cerr << "need more arg" << std::endl;
    }else{
        for (int i=1;i<argc ; i++){
            if (file_exist(argv[i])){
                std::cout << "file " << argv[i] << " exist" << std::endl;
            }else{
                std::cout << "file " << argv[i] << " not exist" << std::endl;
            }
        }
    }
}