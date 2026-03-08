// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/Severity.h"

#include <cstddef>
#include <string>
#include <vector>

namespace lshaz {

enum class TargetArch : uint8_t {
    X86_64,     // 64B cache lines, TSO, MESI coherence
    ARM64,      // 64B cache lines (Graviton), weak ordering
    ARM64Apple, // 128B cache lines (M-series P-cores), weak ordering
};

struct Config {
    // Target architecture (affects cache model, ordering cost model, rule text)
    TargetArch targetArch       = TargetArch::X86_64;

    // Cache model
    size_t cacheLineBytes       = 64;
    size_t cacheLineSpanWarn    = 64;   // FL001 threshold
    size_t cacheLineSpanCrit    = 128;  // FL001 escalation

    // Stack frame
    size_t stackFrameWarnBytes  = 2048; // FL021 threshold

    // Allocation
    size_t allocSizeEscalation  = 256;  // FL020 escalation

    // Branch depth
    unsigned branchDepthWarn    = 4;    // FL050 threshold

    // Minimum severity to emit
    Severity minSeverity        = Severity::Informational;

    // Output
    bool jsonOutput             = false;
    std::string outputFile;             // empty = stdout

    // Hot path patterns (fnmatch-style)
    std::vector<std::string> hotFunctionPatterns;
    std::vector<std::string> hotFilePatterns;

    // Rule enable/disable
    std::vector<std::string> disabledRules;

    // TLB
    size_t pageSize             = 4096;

    // Profile-guided hotness (perf/LBR)
    std::string perfProfilePath;          // Path to perf profile data
    double hotnessThresholdPct  = 1.0;    // Functions with >= N% of samples are hot

    // Allocator topology: linked allocator library name.
    // "tcmalloc", "jemalloc", "mimalloc", or "" (default glibc).
    std::string linkedAllocator;

    static Config loadFromFile(const std::string &path);
    static Config defaults();
};

} // namespace lshaz
