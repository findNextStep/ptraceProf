#pragma once

#include "typedef.hpp"
#include <string>
// #include <sqlite3.h>
#include <nlohmann/json.hpp>

#include <sys/stat.h>
#include "readDump.hpp"
#include <array>
#include <fstream>
#include <iostream>

namespace ptraceProf {

class dumpCache {
public:
    dumpCache(const ::std::string &file) : cache_file(file) {
#ifdef SQLITE3_H
#else
        std::ifstream fs(cache_file);
        if(fs) {
            fs >> json;
        }
#endif

    }
    virtual ~dumpCache() {
#ifdef SQLITE3_H
#else
        std::ofstream fs(cache_file);
        fs << json;
#endif
    }

    std::set<ip_t> get_signle_step(const std::string &file) {
        std::set<ip_t> ans;
        if(has(file)) {
            ans = get(file);
        } else {
            ans = dumpReader::get_single_step_list(file);
            set(file, ans);
        }
        return ans;
    }
protected:

    static auto get_file_last_change_time(const std::string &file) {
        struct stat attrib;
        stat(file.c_str(), &attrib);
        return std::make_pair(attrib.st_mtim.tv_sec, attrib.st_mtim.tv_nsec);
    }

    bool has(const ::std::string &file) const {
#ifdef SQLITE3_H
#else
        if(json.find(file) != json.end()) {
            // 检查是否存在cache中
            auto last_change_time = get_file_last_change_time(file);
            decltype(last_change_time) json_time = json[file]["time"];
            if(last_change_time == json_time) {
                // 检查文件是否改变
                return true;
            }
        }
        return false;
#endif
    }
    std::set<ip_t> get(const std::string &file) const {
#ifdef SQLITE3_H
#else
        return json.at(file).at("time");
#endif
    }

    void set(const std::string &file, const std::set<ip_t> &ans) {
#ifdef SQLITE3_H
#else
        json[file]["addre"] = ans;
        json[file]["time"]  = get_file_last_change_time(file);
#endif
    }

private:
    std::string cache_file;
#ifdef SQLITE3_H
    sqlite3 *db;
#else
    nlohmann::json json;
#endif
};

} // ptraceProf
