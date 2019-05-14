#pragma once

#include "typedef.hpp"
#include <string>
#include <sqlite3.h>
#ifndef SQLITE3_H
#include <nlohmann/json.hpp>
#endif

#include <sys/stat.h>
#include "readDump.hpp"
#include <array>
#include <fstream>
#include <iostream>

namespace ptraceProf {

const static std::string last_modify_time = "last_modify_time";
const static std::string single_step = "single_step";
const static std::string dump = "dump";
const static std::string create_sql[3] = {
    "CREATE TABLE " + last_modify_time +
    "( file TEXT NOT NULL PRIMARY KEY ," +
    " time INTEGER(2) NOT NULL);",

    "CREATE TABLE " + single_step +
    "( file TEXT NOT NULL ," +
    "single_rip INT NOT NULL," +
    "CONSTRAINT files " +
    "FOREIGN KEY (file) " +
    "REFERENCES " + last_modify_time + "(file));",

    "CREATE TABLE " + dump +
    "( file TEXT NOT NULL ," +
    " rip INT NOT NULL," +
    "CONSTRAINT files " +
    "FOREIGN KEY (file) " +
    "REFERENCES " + last_modify_time + "(file));"
};

class dumpCache {
public:
    dumpCache(const ::std::string &file) : cache_file(file) {
#ifdef SQLITE3_H
        if(sqlite3_open(file.c_str(), &db)) {
            std::cerr << "failed to open or create datebase file " << file << std::endl;
            exit(1);
        } else {
            for(int i = 0; i < 3; ++i) {
                exec_sql(create_sql[i]);
            }
        }
#else
        std::ifstream fs(cache_file);
        if(fs) {
            fs >> json;
        }
#endif

    }
    virtual ~dumpCache() {
#ifdef SQLITE3_H
        sqlite3_close(db);
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
        auto last_change_time = get_file_last_change_time(file);
        decltype(last_change_time) sql_time;
        sql_time.first = sql_time.second = 0;
        char *errormsg = nullptr;
        sqlite3_exec(db,
                     ("SELECT time FROM " + last_modify_time + " WHERE file = \"" + file + "\";").c_str(),
        [](void *sql_ptr, int argc, char **argv, char **azColName)->int {
            if(argc) {
                decltype(last_change_time)* time_ptr = (decltype(last_change_time) *)sql_ptr;
                sscanf(argv[0], "%ld,%ld", &time_ptr->first, &time_ptr->second);
            }
            return 0;
        },
        (void *)&sql_time, &errormsg);
        if(!(last_change_time.first == sql_time.first &&
                last_change_time.second == sql_time.second)) {
            std::cout << last_change_time.first << ',' << last_change_time.second << std::endl;
            std::cout << sql_time.first << ',' << sql_time.second << std::endl;
        }
        return last_change_time.first == sql_time.first &&
               last_change_time.second == sql_time.second;
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
        std::set<ip_t> ans;
        char *errormsg = nullptr;
        sqlite3_exec(db,
                     ("SELECT rip FROM " + single_step + " WHERE file = \"" + file + "\";").c_str(),
        [](void *sql_ptr, int argc, char **argv, char **azColName)->int {
            if(argc) {
                std::set<ip_t> *ans = (std::set<ip_t> *)sql_ptr;
                for(int i = 0; i < argc; ++i) {
                    ans->insert(std::stol(argv[i]));
                }
            }
            return 0;
        },
        (void *)&ans, &errormsg);
        return ans;
#else
        return json.at(file).at("time");
#endif
    }

    void set(const std::string &file, const std::set<ip_t> &ans) {
#ifdef SQLITE3_H
        exec_sql("delete from " + dump + " where file = \"" + file + "\";");
        exec_sql("delete from " + last_modify_time + " where file = \"" + file + "\";");
        exec_sql("delete from " + single_step + " where file = \"" + file + "\";");
        {
            const auto change_time = get_file_last_change_time(file);
            exec_sql("insert into " + last_modify_time + " VALUES(\"" + file + "\",\"" +
                     std::to_string(change_time.first) + "," + std::to_string(change_time.second) + "\");");
            std::string command = "begin;";
            std::cout << "make command" << std::endl;
            for(const auto i : ans) {
                command += ("insert into " + single_step + " VALUES(\"" + file + "\",\"" +
                            std::to_string(i) + "\");");
            }
            command += "commit;";
            std::cout << "launch command" << std::endl;
            exec_sql(command);
            std::cout << "command over" << std::endl;
        }
#else
        json[file]["addre"] = ans;
        json[file]["time"]  = get_file_last_change_time(file);
#endif
    }

private:
    std::string cache_file;
#ifdef SQLITE3_H
    sqlite3 *db;
    bool exec_sql(const std::string &sql_command) {
        char *errormsg = nullptr;
        return sqlite3_exec(
                   db, sql_command.c_str(),
                   [](void *, int, char **, char **)->int { return 0; }
                   , 0, &errormsg) == SQLITE_OK;
    }
#else
    nlohmann::json json;
#endif
};

} // ptraceProf