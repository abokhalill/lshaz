#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace faultline {

// Parses perf profile data to identify hot functions.
//
// Supported formats:
//   1. Flat: "<demangled_function_name> <sample_count>" per line
//   2. perf-script: extracts function symbols from "perf script" output
//      (lines matching: <comm> <pid> <cpu> <timestamp>: <event> <addr> <sym>+<off> (<dso>))
//
// Returns function names exceeding the sample threshold as a fraction
// of total samples.
class PerfProfileParser {
public:
    struct ProfileEntry {
        std::string functionName;
        uint64_t sampleCount = 0;
        double pct = 0.0;
    };

    // Parse a profile file. Returns false on I/O error.
    bool parse(const std::string &path);

    // Get function names exceeding thresholdPct of total samples.
    std::unordered_set<std::string> hotFunctions(double thresholdPct) const;

    const std::vector<ProfileEntry> &entries() const { return entries_; }
    uint64_t totalSamples() const { return totalSamples_; }

private:
    bool parseFlat(const std::string &content);
    bool parsePerfScript(const std::string &content);

    std::vector<ProfileEntry> entries_;
    std::unordered_map<std::string, uint64_t> symbolCounts_;
    uint64_t totalSamples_ = 0;
};

} // namespace faultline
