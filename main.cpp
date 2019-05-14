#include "processTrace.hpp"
#include "afterProcess.hpp"
#include <iostream>
#include <nlohmann/json.hpp>

int main(const int argc, char *argv[]) {
    std::string final_result_file;
    std::string addre_count_file, function_count_file;
#ifdef SQLITE3_H
    std::string objdump_cache = "/tmp/objdump.db";
#else
    std::string objdump_cache = "/tmp/objdump.json";
#endif
    bool single_step = false, full_trace = false;
    const std::vector<std::string> args(argv, argv + argc);
    int trace_time = 10, gap = 0;
    unsigned int last_command_pos = argc;
    for(unsigned int i = 1; i < args.size(); ++i) {
        const std::string arg = args[i];
        if(arg == "-c" || arg == "--single-step") {
            single_step = true;
        } else if(arg == "-e" || arg == "--exec") {
            last_command_pos = i + 1;
            break;
        } else if(arg == "-r" || arg == "--final-file") {
            final_result_file = args[++i];
        } else if(arg == "-d" || arg == "--addre-file") {
            addre_count_file = args[++i];
        } else if(arg == "-f" || arg == "--func-file") {
            function_count_file = args[++i];
        } else if(arg == "-a" || arg == "--full") {
            full_trace = true;
        } else if(arg == "-t" || arg == "--trace-time") {
            trace_time = std::stoi(args[++i]);
        } else if(arg == "-g" || arg == "--gap") {
            gap = std::stoi(args[++i]);
        } else {
            std::cerr << arg << std::endl;
            return 1;
        }
    }
    const int child = fork();
    if(child == 0) {
        // in tracee process
        ::ptraceProf::ptraceThisProcess();
        std::string process_name = "tracee with ";
        if(argc == last_command_pos) {
            execlp("./a.out", "out");
        } else {
            execvp(argv[last_command_pos], argv + last_command_pos);
        }
        return 0;
    }
    // in tracer porcess
    std::cout << "child_pid == " << child;
    // command line value check
    ::ptraceProf::processProf pp(objdump_cache);
    std::map<std::string, std::map<std::string, ::ptraceProf::count_t> > ans;
    if(single_step) {
        std::cout << "\tin single step" << std::endl;
        auto [count, maps] = ::ptraceProf::dump_and_trace_sign(child);
        std::cout << "finish" << std::endl;
        if(final_result_file.size()) {
            ans = ::ptraceProf::analize_count(maps, count);
        }
    } else {
        std::cout << "\tin block step" << std::endl;
        if(!full_trace) {
            pp.trace(child, trace_time, gap);
        } else {
            pp.traceFull(child);
        }
        std::cout << "finish" << std::endl;
        if(final_result_file.size()) {
            ans = pp.analize_count();
        }
    }
    if(final_result_file.size()) {
        std::ofstream of(final_result_file);
        of << ::nlohmann::json(ans).dump(4);
    }
    if(function_count_file.size()) {
        if(final_result_file.empty()) {
            ans = pp.analize_count();
        }
        std::ofstream of(function_count_file);
        for(auto [name, time] : ::ptraceProf::order_output_function(ans)) {
            of << name << '\t' << time << '\n';
        }
    }
    if(addre_count_file.size()) {
        if(final_result_file.empty()) {
            ans = pp.analize_count();
        }
        std::ofstream of(addre_count_file);
        for(auto [name, time] : ::ptraceProf::order_output(ans)) {
            of << name << '\t' << time << '\n';
        }
    }
    return 0;
}


