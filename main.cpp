#include "processTrace.hpp"
#include <iostream>
#include <nlohmann/json.hpp>
#include "gethin.hpp"

int main(int argc, char **argv) {
    gethin::Flag single_step = gethin::Flag()
                               .shortOpt('s')
                               .longOpt("single_step")
                               .help("decisiion whether use single step test");
    gethin::String step_file = gethin::String()
                               .longOpt("step-file")
                               .help("output file for process step. If no set ,while output to stderr");
    gethin::String final_result_file = gethin::String()
                                       .shortOpt('r')
                                       .longOpt("final_result_file")
                                       .help("the file for ans as {file:[offset,time]} in json. If no set, won`t output");
    gethin::String exec_path = gethin::String()
                               .longOpt("exec_path")
                               .shortOpt('c')
                               .help("exeable file path. will be ./a.out in default");
    gethin::OptionReader optReader({
        &single_step,
        &step_file,
        &final_result_file,
        &exec_path,
    }, "ptraceProf");
    if(argc > 1) {
        try {
            optReader.read(argc, argv);
        } catch(const std::invalid_argument &e) {
            std::cerr << e.what() << std::endl;
            return 1;
        } catch(...) {
            std::cerr << "Error during execution!" << std::endl;
            return 1;
        }
    }

    int child = fork();
    if(child == 0) {
        // in tracee process
        ::ptraceProf::ptraceThisProcess();
        if(exec_path.value().empty()) {
            execl("./a.out", "out");
        } else {
            execl(exec_path.value().c_str(), "tracee");
        }
    }
    // in tracer porcess
    std::cout << "child_pid == " << child;
    // command line value check
    if(step_file.value().size()) {
        freopen(step_file.value().c_str(), "w", stderr);
    }
    ::ptraceProf::processProf pp;

    std::map<std::string, std::map<std::string, int> > ans;
    if(single_step.value()) {
        std::cout << "\tin single step" << std::endl;
        auto [count, maps] = ::ptraceProf::dump_and_trace_sign(child);
        std::cout << "finish" << std::endl;
        if(final_result_file.value().size()) {
            ans = ::ptraceProf::analize(count, maps);
            std::ofstream of(final_result_file.value());
            of << ::nlohmann::json(ans).dump(4);
        } else {
            ans = ::ptraceProf::analize(count, maps);
            std::cerr << ::nlohmann::json(ans).dump(4);
        }
    } else {
        std::cout << "\tin block step" << std::endl;
        pp.trace(child);
        std::cout << "finish" << std::endl;
        if(final_result_file.value().size()) {
            ans = pp.analize();
            std::ofstream of(final_result_file.value());
            of << ::nlohmann::json(ans).dump(4);
        } else {
            ans = pp.analize();
            std::cerr << ::nlohmann::json(ans).dump(4);
        }
    }
    return 0;
}


