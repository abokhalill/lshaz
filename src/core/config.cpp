// SPDX-License-Identifier: Apache-2.0
#include <cstdlib>
#include "lshaz/core/config.h"

#include <llvm/Support/YAMLParser.h>
#include <llvm/Support/YAMLTraits.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <fstream>
#include <sstream>

// YAML mapping for Config via llvm::yaml.
// Using LLVM's built-in YAML support, no third-party dependency.

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
        io.mapOptional("infer_hot_paths",        cfg.inferHotPaths);
        io.mapOptional("hot_function_patterns",  cfg.hotFunctionPatterns);
        io.mapOptional("hot_file_patterns",      cfg.hotFilePatterns);
        io.mapOptional("vendor_path_patterns",   cfg.vendorPathPatterns);
        io.mapOptional("skip_vendored",          cfg.skipVendored);
        io.mapOptional("numa_sockets",           cfg.numaSockets);
        io.mapOptional("coherence_domains",      cfg.coherenceDomains);
        io.mapOptional("disabled_rules",         cfg.disabledRules);
        io.mapOptional("page_size",              cfg.pageSize);
        io.mapOptional("perf_profile_path",      cfg.perfProfilePath);
        io.mapOptional("hotness_threshold_pct",  cfg.hotnessThresholdPct);
        io.mapOptional("linked_allocator",       cfg.linkedAllocator);
        io.mapOptional("target_arch",             cfg.targetArch);
        io.mapOptional("atomic_type_names",      cfg.atomicTypeNames);
        io.mapOptional("thread_entry_patterns",  cfg.threadEntryPatterns);
        io.mapOptional("main_function_patterns", cfg.mainFunctionPatterns);
        io.mapOptional("smt_enabled",            cfg.smtEnabled);
        io.mapOptional("l1d_size_bytes",         cfg.l1dSizeBytes);
        io.mapOptional("machine_name",           cfg.machineName);
        io.mapOptional("cycles_hitm_local",      cfg.cyclesHitmLocal);
        io.mapOptional("cycles_hitm_remote",     cfg.cyclesHitmRemote);
        io.mapOptional("cycles_dram",            cfg.cyclesDram);
        io.mapOptional("cycles_mispredict",      cfg.cyclesMispredict);
        io.mapOptional("mlp_overlap_pct",        cfg.mlpOverlapPct);
        io.mapOptional("workload_cycles_per_op", cfg.workloadCyclesPerOp);
        io.mapOptional("workload_name",          cfg.workloadName);
        io.mapOptional("workload_sharers",       cfg.workloadSharers);
        io.mapOptional("cost_calibration_path",  cfg.costCalibrationPath);
        io.mapOptional("dispatch_path_patterns", cfg.dispatchPathPatterns);
        io.mapOptional("tick_path_patterns",     cfg.tickPathPatterns);
        io.mapOptional("relax_function_patterns", cfg.relaxFunctionPatterns);
        io.mapOptional("thread_index_patterns",  cfg.threadIndexPatterns);
        io.mapOptional("lock_function_patterns",   cfg.lockFunctionPatterns);
        io.mapOptional("mapping_function_patterns",
                       cfg.mappingFunctionPatterns);
        io.mapOptional("unlock_function_patterns", cfg.unlockFunctionPatterns);
        io.mapOptional("allocator_function_patterns",
                       cfg.allocatorFunctionPatterns);
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

    // cacheLineBytes is a divisor in every layout computation. Zero crashed
    // each TU.
    auto isPow2 = [](uint64_t v) { return v && (v & (v - 1)) == 0; };
    if (!isPow2(cfg.cacheLineBytes) || cfg.cacheLineBytes < 8 ||
        cfg.cacheLineBytes > 4096) {
        llvm::errs() << "lshaz: FATAL: cache_line_bytes is "
                     << cfg.cacheLineBytes
                     << "; expected a power of two in [8, 4096]. Every layout "
                        "computation divides by it.\n";
        std::exit(3);
    }

    return cfg;
}

} // namespace lshaz
