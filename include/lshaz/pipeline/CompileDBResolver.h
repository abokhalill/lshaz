#pragma once

#include <string>
#include <vector>

namespace lshaz {

class CompileDBResolver {
public:
    // Search for compile_commands.json in standard locations relative to
    // the given project root. Returns the first found path, or empty string.
    static std::string discover(const std::string &projectRoot);

    // Candidate paths searched, in priority order.
    static std::vector<std::string> candidatePaths(const std::string &projectRoot);
};

} // namespace lshaz
