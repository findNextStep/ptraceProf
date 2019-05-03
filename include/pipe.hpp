#pragma once
#include <sys/types.h>
#include <sys/stat.h>
#include <iostream>
#include <fstream>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <math.h>
#include <cstdio>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <array>
#include <sstream>

namespace ptraceProf {

std::stringstream get_cmd_stream(const std::string &&cmd);

}