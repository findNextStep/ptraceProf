#pragma once
#include <string>
#include <vector>

namespace ptraceProf {
/* ip point */
using ip_t = unsigned long long;
/* count number type */
using count_t = unsigned long long;
/**
 * @brief start_with if string is start with
 *
 * @param base the string that need to be query
 * @param head the head that base_string should have
 *
 * @return if base is start with bead
 */
bool start_with(const std::string &base, const std::string &head);

/**
 * @brief force_jump whether the command is a unconditional jump
 *
 * @param info the command info from objdump
 *
 * @return 0 for not a unconditional jump command
 * @return -1 for unconditional jump but not know where to go
 * @return unconditional jump address
 */
ip_t force_jump(const std::string &info);

/**
 * @brief may_jump whether the command is a conditional jump

 *
 * @param info the command info from objdump
 *
 * @return 0 for not a conditional jump command
 * @return conditional jump address
 */
ip_t may_jump(const std::string &info);

/**
 * @brief may_jump whether the command is a conditional jump and the address
 *
 * @param info the command info from objdump
 * @param next_addre jump aim
 *
 * @return if the command is jump to next_addre
 */
bool may_jump(const std::string &info, const ip_t next_addre);

/**
 * @brief need_check if the command need single step check
 *
 * @param info the command info from objdump
 *
 * @return if the command need check
 */
bool need_check(const std::string &info);

/**
 * @brief lltoString change long long to hex string
 *
 * @param num
 *
 * @return the hex string for num
 */
std::string lltoString(long long);



} // ptraceProf
