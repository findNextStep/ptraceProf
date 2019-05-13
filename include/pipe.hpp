#pragma once
#include <string>
#include <sstream>

namespace ptraceProf {

std::stringstream get_cmd_stream(const std::string &&cmd);

}