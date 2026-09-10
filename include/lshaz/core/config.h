// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/severity.h"

#include <cstddef>
#include <set>
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

    // Deployment runs with SMT/Hyper-Threading enabled. Reported in FL013's
    // evidence only. It used to move that rule's severity a notch, until
    // sync_cost measured 0.0% sibling recovery on two vendors.
    bool smtEnabled             = true;

    // Cache model
    size_t cacheLineBytes       = 64;
    size_t cacheLineSpanWarn    = 64;   // FL001 threshold
    size_t cacheLineSpanCrit    = 128;  // FL001 escalation

    // Stack frame
    size_t stackFrameWarnBytes  = 2048; // FL021 threshold

    // FL020 escalation, set at glibc's tcache_max. At or below it a request is
    // served from the per-thread cache; above it the arena path costs 2.8x
    // (19.3ns to 55.4ns, Zen 3). The previous 256 graded a curve that is flat
    // from 32B to 1032B. tcmalloc and jemalloc draw the line elsewhere.
    size_t allocSizeEscalation  = 1032;

    // Branch depth
    unsigned branchDepthWarn    = 4;    // FL050 threshold

    // Minimum severity to emit
    Severity minSeverity        = Severity::Informational;

    // Output
    bool jsonOutput             = false;
    std::string outputFile;             // empty = stdout

    // Hot path patterns (fnmatch-style)
    // Derive hotness from loop-depth reachability when no attribute,
    // config pattern or profile supplies it. Without this, an
    // unconfigured scan leaves every hot-path rule inert.
    bool inferHotPaths = true;
    std::vector<std::string> hotFunctionPatterns;
    std::vector<std::string> hotFilePatterns;

    // Vendored third-party trees, skipped unless --include-vendored or
    // skip_vendored: false. Directory naming is convention, not fact, so a
    // project whose own code lives under one of these names must be able to
    // replace the list. Set vendor_path_patterns to the trees that really
    // are vendored. A non-empty list replaces these defaults; use
    // skip_vendored to turn the behaviour off, since YAML's empty sequence
    // is indistinguishable from an absent key here.
    bool skipVendored = true;
    std::vector<std::string> vendorPathPatterns = {
        "*/deps/*", "*/third_party/*", "*/thirdparty/*", "*/third-party/*",
        "*/vendor/*", "*/external/*", "*/extern/*", "*/contrib/*",
        "*/node_modules/*", "*/subprojects/*",
    };

    // Deployment socket count. Unlike the preconditions other rules assume,
    // this one cannot be read from source; it is a property of
    // where the binary runs. 0 means unknown, and FL060 then reports with
    // the assumption labelled.
    unsigned numaSockets = 0;

    // Last-level-cache domains on the target, which is not socket count: a
    // 5950X is one socket, one NUMA node, two CCDs. FL002's density decay
    // holds only within a domain. 0 is unknown and declines to demote.
    unsigned coherenceDomains = 0;

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

    // Opaque atomic wrapper type names (e.g. atomic_t, spinlock_t).
    std::vector<std::string> atomicTypeNames;

    // L1 data cache size; FL003 weighs padding footprint against it.
    size_t l1dSizeBytes = 32768;

    // Cost model inputs, all measured on the target being scanned for and
    // supplied here rather than compiled in. Zero means unmeasured, and any
    // term consuming a zero reports itself as a stand-in.
    std::string machineName;
    unsigned cyclesHitmLocal = 0;
    unsigned cyclesHitmRemote = 0;
    unsigned cyclesDram = 0;
    unsigned cyclesMispredict = 0;
    unsigned mlpOverlapPct = 0;

    // A property of the workload, not the hardware. Without it a cost cannot
    // be read as a share of an operation and nothing is graded on it.
    unsigned workloadCyclesPerOp = 0;

    // Names the workload the figures above were measured under, so a
    // residual learned on one shape is not applied to another.
    std::string workloadName;

    // Observations of predicted against measured cost. Each one corrects the
    // mechanism rather than the finding it came from, so a measurement taken
    // on one target improves every scan that composes the same terms.
    std::string costCalibrationPath;

    // Write-frequency roots for FL003 (fnmatch). Hot comes from the
    // hot-path oracle; these name the slower tiers so a real hazard on a
    // per-connection path is not priced as if it were per-command.
    std::vector<std::string> dispatchPathPatterns;
    std::vector<std::string> tickPathPatterns;

    // Thread-role attribution roots (fnmatch-style). Entry patterns name
    // worker-thread roots that thread-creation detection cannot see
    // (function-pointer dispatch); main patterns extend the ROLE_MAIN
    // seed beyond main() for callbacks dispatched from its event loop.
    std::vector<std::string> threadEntryPatterns;
    std::vector<std::string> mainFunctionPatterns;

    // Bespoke backoff/wait vocabularies (fnmatch on plain or qualified
    // names) granted FL013 relax immunity. The standard universe is
    // built in.
    std::vector<std::string> relaxFunctionPatterns;

    // Allocator wrappers (fnmatch) added to FL020's built-in set. Without
    // them a codebase reaching libc through zmalloc, ngx_palloc or kmalloc
    // shows no allocation at all.
    std::vector<std::string> allocatorFunctionPatterns;

    // Derived by the vocabulary prepass from structure, not set by the user
    // and not YAML-mapped. Exact names rather than globs, because they were
    // computed rather than guessed. allocator_function_patterns still exists
    // for allocators the prepass cannot see: one whose body is never compiled,
    // or whose result leaves through an out-parameter.
    std::set<std::string> derivedAllocatorNames;
    std::set<std::string> derivedFreeNames;
    std::set<std::string> derivedMappingNames;
    std::set<std::string> derivedLockNames;
    std::set<std::string> derivedUnlockNames;
    // "F|i": parameter i of F carries a thread identity.
    std::set<std::string> threadIdentParams;

    // Per-TU result cache directory. Empty disables it. Not YAML-mapped: a
    // cache is a property of the machine running the scan, not of the project.
    std::string cacheDir;
    unsigned cacheMaxMB = 4096;

    // Lock wrappers (fnmatch) added to FL012's POSIX set. nginx reaches its
    // mutexes through ngx_shmtx_lock at 48 sites and pthread_mutex_lock at 2,
    // so without these the rule sees 4% of the locks in that tree. Acquire and
    // release are separate lists because nesting depth is a count: guessing
    // the release side from the spelling desynchronizes it on the first
    // wrapper that does not say "unlock".
    std::vector<std::string> lockFunctionPatterns;
    std::vector<std::string> unlockFunctionPatterns;

    // Large-mapping wrappers for FL070, "name" or "name:N" where N is the
    // zero-based size parameter (default 0). A 4MB mapping through a one-line
    // wrapper is invisible otherwise, while the identical direct mmap fires.
    std::vector<std::string> mappingFunctionPatterns;

    // Project names for a thread-slot index (fnmatch), added to FL003's
    // built-in set. Kept out of that set because `slot` and `shard` name
    // hash buckets and ring positions at least as often.
    std::vector<std::string> threadIndexPatterns;

    static Config loadFromFile(const std::string &path);
    static Config defaults();
};

} // namespace lshaz
