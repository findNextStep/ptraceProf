#pragma once

#include "typedef.hpp"
#include <string>
#include <sqlite3.h>
#include <set>
#ifndef SQLITE3_H
#include <nlohmann/json.hpp>
#endif

namespace ptraceProf {

class dumpCache {
public:
    dumpCache(const ::std::string &file);
    virtual ~dumpCache();

    std::set<ip_t> get_signle_step(const std::string &file);
    std::set<ip_t> get_full_dump(const std::string &file);
protected:

    static auto get_file_last_change_time(const std::string &file);

    bool has(const ::std::string &file) const;
    std::set<ip_t> get_named_set(const std::string &file,const std::string &name)const;
    std::set<ip_t> get_single_step_set(const std::string &file)const ;
    std::set<ip_t> get_full_dump_set(const std::string &file)const ;

    void set(const std::string &file, const std::pair<std::set<ip_t>, std::set<ip_t> > &ans);

private:
    std::string cache_file;
#ifdef SQLITE3_H
    bool exec_sql(const std::string &sql_command);
    sqlite3 *db;
#else
    nlohmann::json json;
#endif
};

} // ptraceProf
