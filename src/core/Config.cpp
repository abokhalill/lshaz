// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Config.h"

#include <llvm/Support/YAMLParser.h>
#include <llvm/Support/YAMLTraits.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <fstream>
#include <sstream>

// YAML mapping for Config via llvm::yaml.
// Using LLVM's built-in YAML support — no third-party dependency.

namespace llvm {
namespace yaml {

template <>
struct ScalarEnumerationTraits<lshaz::TargetArch> {
    static void enumeration(IO &io, lshaz::TargetArch &arch) {
        io.enumCase(arch, "x86-64",      lshaz::TargetArch::X86_64);
        io.enumCase(arch, "x86_64",      lshaz::TargetArch::X86_64);
        io.enumCase(arch, "arm64",       lshaz::TargetArch::ARM64);
        io.enumCase(arch, "arm64-apple", lshaz::TargetArch::ARM64Apple);
    }
};

template <>
struct MappingTraits<lshaz::Config> {
    static void mapping(IO &io, lshaz::Config &cfg) {
        io.mapOptional("cache_line_bytes",       cfg.cacheLineBytes);
        io.mapOptional("cache_line_span_warn",   cfg.cacheLineSpanWarn);
        io.mapOptional("cache_line_span_crit",   cfg.cacheLineSpanCrit);
        io.mapOptional("stack_frame_warn_bytes", cfg.stackFrameWarnBytes);
        io.mapOptional("alloc_size_escalation",  cfg.allocSizeEscalation);
        io.mapOptional("branch_depth_warn",      cfg.branchDepthWarn);
        io.mapOptional("json_output",            cfg.jsonOutput);
        io.mapOptional("output_file",            cfg.outputFile);
        io.mapOptional("hot_function_patterns",  cfg.hotFunctionPatterns);
        io.mapOptional("hot_file_patterns",      cfg.hotFilePatterns);
        io.mapOptional("disabled_rules",         cfg.disabledRules);
        io.mapOptional("page_size",              cfg.pageSize);
        io.mapOptional("perf_profile_path",      cfg.perfProfilePath);
        io.mapOptional("hotness_threshold_pct",  cfg.hotnessThresholdPct);
        io.mapOptional("linked_allocator",       cfg.linkedAllocator);
        io.mapOptional("target_arch",             cfg.targetArch);
        io.mapOptional("atomic_type_names",      cfg.atomicTypeNames);
    }
};

} // namespace yaml
} // namespace llvm

namespace lshaz {

Config Config::defaults() {
    return Config{};
}

Config Config::loadFromFile(const std::string &path) {
    auto bufOrErr = llvm::MemoryBuffer::getFile(path);
    if (!bufOrErr) {
        llvm::errs() << "lshaz: warning: cannot open config '"
                     << path << "', using defaults\n";
        return defaults();
    }

    Config cfg = defaults();
    llvm::yaml::Input yin(bufOrErr.get()->getBuffer());
    yin >> cfg;

    if (yin.error()) {
        llvm::errs() << "lshaz: warning: config parse error in '"
                     << path << "', using defaults\n";
        return defaults();
    }

    // Apply architecture defaults when target_arch is set but cache model
    // fields were not explicitly overridden (still at x86-64 defaults).
    if (cfg.targetArch == TargetArch::ARM64Apple) {
        Config def;
        if (cfg.cacheLineBytes == def.cacheLineBytes)
            cfg.cacheLineBytes = 128;
        if (cfg.cacheLineSpanWarn == def.cacheLineSpanWarn)
            cfg.cacheLineSpanWarn = 128;
        if (cfg.cacheLineSpanCrit == def.cacheLineSpanCrit)
            cfg.cacheLineSpanCrit = 256;
    }

    return cfg;
}

} // namespace lshaz
