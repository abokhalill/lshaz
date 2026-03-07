#pragma once

#include "lshaz/pipeline/ScanRequest.h"

#include <string>
#include <vector>

namespace lshaz {

bool matchesGlob(const std::string &path, const std::string &pattern);

std::vector<std::string> filterSources(
    const std::vector<std::string> &sources,
    const FilterOptions &filter);

} // namespace lshaz
