#include "faultline/core/PerfProfileParser.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace faultline {

bool PerfProfileParser::parse(const std::string &path) {
    std::ifstream file(path);
    if (!file.is_open())
        return false;

    std::string content((std::istreambuf_iterator<char>(file)),
                         std::istreambuf_iterator<char>());

    if (content.empty())
        return false;

    // Heuristic: perf script output contains lines with timestamps like
    // "comm pid cpu timestamp: event". Flat format has "name count".
    bool hasPerfScriptMarkers = false;
    std::istringstream probe(content);
    std::string probeLine;
    for (int i = 0; i < 10 && std::getline(probe, probeLine); ++i) {
        if (probeLine.find(':') != std::string::npos &&
            probeLine.find('+') != std::string::npos) {
            hasPerfScriptMarkers = true;
            break;
        }
    }

    return hasPerfScriptMarkers ? parsePerfScript(content) : parseFlat(content);
}

bool PerfProfileParser::parseFlat(const std::string &content) {
    // Format: "<function_name> <sample_count>" per line.
    // Lines starting with '#' are comments.
    std::istringstream stream(content);
    std::string line;

    while (std::getline(stream, line)) {
        if (line.empty() || line[0] == '#')
            continue;

        // Find last space-separated token as count.
        auto lastSpace = line.rfind(' ');
        if (lastSpace == std::string::npos || lastSpace == 0)
            continue;

        std::string countStr = line.substr(lastSpace + 1);
        std::string funcName = line.substr(0, lastSpace);

        // Trim whitespace.
        while (!funcName.empty() && std::isspace(funcName.back()))
            funcName.pop_back();
        while (!countStr.empty() && std::isspace(countStr.front()))
            countStr.erase(countStr.begin());

        if (funcName.empty() || countStr.empty())
            continue;

        // Parse count — must be numeric.
        uint64_t count = 0;
        bool numeric = true;
        for (char c : countStr) {
            if (!std::isdigit(c)) { numeric = false; break; }
        }
        if (!numeric)
            continue;

        count = std::stoull(countStr);
        symbolCounts_[funcName] += count;
        totalSamples_ += count;
    }

    // Build sorted entries.
    for (const auto &[name, count] : symbolCounts_) {
        ProfileEntry e;
        e.functionName = name;
        e.sampleCount = count;
        entries_.push_back(std::move(e));
    }

    // Compute percentages.
    if (totalSamples_ > 0) {
        for (auto &e : entries_)
            e.pct = 100.0 * static_cast<double>(e.sampleCount) /
                    static_cast<double>(totalSamples_);
    }

    std::sort(entries_.begin(), entries_.end(),
              [](const ProfileEntry &a, const ProfileEntry &b) {
                  return a.sampleCount > b.sampleCount;
              });

    return totalSamples_ > 0;
}

bool PerfProfileParser::parsePerfScript(const std::string &content) {
    // perf script output format (simplified):
    //   <comm> <pid>/<tid> [<cpu>] <timestamp>: <event>:
    //         <addr> <symbol>+<offset> (<dso>)
    //
    // We extract <symbol> from lines containing '+0x' pattern.
    std::istringstream stream(content);
    std::string line;

    while (std::getline(stream, line)) {
        // Symbol lines typically have a hex address followed by symbol+offset.
        auto plusPos = line.find('+');
        if (plusPos == std::string::npos)
            continue;

        // Verify there's a hex offset after '+'
        if (plusPos + 1 >= line.size() || line[plusPos + 1] != '0')
            continue;

        // Extract symbol: scan backwards from '+' to find the start.
        auto symEnd = plusPos;
        auto symStart = line.rfind(' ', symEnd);
        if (symStart == std::string::npos)
            continue;
        ++symStart; // skip space

        std::string sym = line.substr(symStart, symEnd - symStart);
        if (sym.empty() || sym[0] == '[') // skip [kernel.kallsyms] etc.
            continue;

        symbolCounts_[sym]++;
        totalSamples_++;
    }

    for (const auto &[name, count] : symbolCounts_) {
        ProfileEntry e;
        e.functionName = name;
        e.sampleCount = count;
        entries_.push_back(std::move(e));
    }

    if (totalSamples_ > 0) {
        for (auto &e : entries_)
            e.pct = 100.0 * static_cast<double>(e.sampleCount) /
                    static_cast<double>(totalSamples_);
    }

    std::sort(entries_.begin(), entries_.end(),
              [](const ProfileEntry &a, const ProfileEntry &b) {
                  return a.sampleCount > b.sampleCount;
              });

    return totalSamples_ > 0;
}

std::unordered_set<std::string>
PerfProfileParser::hotFunctions(double thresholdPct) const {
    std::unordered_set<std::string> result;
    for (const auto &e : entries_) {
        if (e.pct >= thresholdPct)
            result.insert(e.functionName);
    }
    return result;
}

} // namespace faultline
