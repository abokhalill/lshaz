#include "lshaz/pipeline/SourceFilter.h"

namespace lshaz {

bool matchesGlob(const std::string &path, const std::string &pattern) {
    if (pattern.empty())
        return false;

    if (pattern.front() == '*' && pattern.back() == '*' && pattern.size() > 2) {
        std::string sub = pattern.substr(1, pattern.size() - 2);
        return path.find(sub) != std::string::npos;
    }
    if (pattern.front() == '*') {
        std::string suffix = pattern.substr(1);
        return path.size() >= suffix.size() &&
               path.compare(path.size() - suffix.size(), suffix.size(), suffix) == 0;
    }
    return path.find(pattern) != std::string::npos;
}

std::vector<std::string> filterSources(
        const std::vector<std::string> &sources,
        const FilterOptions &filter) {
    std::vector<std::string> result;
    result.reserve(sources.size());

    for (const auto &src : sources) {
        if (!filter.includeFiles.empty()) {
            bool matched = false;
            for (const auto &pat : filter.includeFiles) {
                if (matchesGlob(src, pat)) { matched = true; break; }
            }
            if (!matched) continue;
        }

        bool excluded = false;
        for (const auto &pat : filter.excludeFiles) {
            if (matchesGlob(src, pat)) { excluded = true; break; }
        }
        if (excluded) continue;

        result.push_back(src);

        if (filter.maxFiles > 0 && result.size() >= filter.maxFiles)
            break;
    }
    return result;
}

} // namespace lshaz
