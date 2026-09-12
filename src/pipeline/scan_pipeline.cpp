// SPDX-License-Identifier: Apache-2.0
#include "lshaz/pipeline/scan_pipeline.h"
#include "shard_ipc.h"

#include "lshaz/analysis/contention.h"
#include "lshaz/analysis/memory.h"
#include "lshaz/pipeline/abs_path_db.h"
#include "lshaz/pipeline/compile_db.h"
#include "lshaz/pipeline/filter.h"
#include "lshaz/pipeline/tu_cache.h"

#include "lshaz/analysis/action.h"
#include "lshaz/analysis/cache_line.h"
#include "lshaz/analysis/rate_model.h"
#include "lshaz/core/cost.h"
#include "lshaz/core/cost_calibration.h"
#include "lshaz/analysis/vocabulary.h"
#include "lshaz/core/dedup.h"
#include "lshaz/core/hot_path.h"
#include "lshaz/core/interaction.h"
#include "lshaz/core/perf_profile.h"
#include "lshaz/core/precision.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/version.h"
#include "lshaz/hypothesis/calibration.h"
#include "lshaz/hypothesis/hypothesis.h"
#include "lshaz/hypothesis/pmu_trace.h"
#include "lshaz/ir/refiner.h"
#include "lshaz/ir/ir_analyzer.h"
#include "lshaz/ir/opt_remark.h"

#include <clang/Basic/Version.inc>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/ADT/StringSet.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MD5.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/CrashRecoveryContext.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <map>
#include <unordered_set>
#include <vector>

#include <csignal>
#include <fnmatch.h>
#include <charconv>
#include <cstdio>
#include <cstring>
#include <new>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace lshaz {

ScanPipeline::ScanPipeline(ProgressCallback progress)
    : progress_(std::move(progress)) {}

void ScanPipeline::report(const std::string &stage,
                           const std::string &detail) const {
    if (progress_)
        progress_(stage, detail);
}

// --- IR emission helpers (internal) ---

namespace {

// GCC-only flags Clang rejects. A GCC-configured compile database carries
// them, and clang fails the whole IR emission rather than ignoring them.
bool isGCCOnlyFlag(llvm::StringRef arg) {
    // Exact matches
    static const llvm::StringSet<> exactFlags = {
        "-fno-strict-overflow",
        "-fno-delete-null-pointer-checks",
        "-fno-allow-store-data-races",
        "-fno-reorder-blocks",
        "-fno-ipa-cp-clone",
        "-fno-partial-inlining",
        "-fno-tree-loop-distribute-patterns",
        "-fconserve-stack",
        "-fno-stack-clash-protection",
        "-mno-fp-ret-in-387",
        "-mpreferred-stack-boundary=3",
        "-mskip-rax-setup",
        "-mrecord-mcount",
        "-mfentry",
        "-mindirect-branch=thunk-extern",
        "-mindirect-branch-register",
        "-mindirect-branch-cs-prefix",
        "-mfunction-return=thunk-extern",
        "-fno-jump-tables",
        "-fno-gcse",
        "-fno-tree-scev-cprop",
        "-fno-PIE",
        "-fno-asynchronous-unwind-tables",
        "-fzero-call-used-regs=used-gpr",
        "-fstrict-flex-arrays=3",
        "-fno-strict-flex-arrays",
        // clang-18 crashes on this with -c. Harmless while emission is
        // -S -emit-llvm, fatal the moment anything runs codegen.
        "-ffat-lto-objects",
        "-fno-fat-lto-objects",
    };
    if (exactFlags.contains(arg))
        return true;

    // Prefix matches for parameterized flags
    if (arg.starts_with("-Wshadow="))           // -Wshadow=compatible-local
        return true;
    if (arg.starts_with("-Wcast-function-type"))  // -Wcast-function-type
        return true;
    if (arg.starts_with("-Wimplicit-fallthrough="))  // -Wimplicit-fallthrough=3
        return true;
    if (arg.starts_with("-Wno-stringop-"))      // -Wno-stringop-truncation, etc.
        return true;
    if (arg.starts_with("-Wstringop-"))
        return true;
    if (arg.starts_with("-Wno-format-truncation"))
        return true;
    if (arg.starts_with("-Wformat-truncation"))
        return true;
    if (arg.starts_with("-Wno-maybe-uninitialized"))
        return true;
    if (arg.starts_with("-Wmaybe-uninitialized"))
        return true;
    if (arg.starts_with("-Wno-alloc-size-larger-than"))
        return true;
    if (arg.starts_with("-Walloc-size-larger-than"))
        return true;
    if (arg.starts_with("-Wno-restrict"))
        return true;
    if (arg.starts_with("-Wduplicated-"))       // -Wduplicated-cond, -Wduplicated-branches
        return true;
    if (arg.starts_with("-Wlogical-op"))
        return true;
    if (arg.starts_with("-Wno-aggressive-loop-optimizations"))
        return true;
    if (arg.starts_with("-mabi="))              // -mabi=lp64
        return true;
    if (arg.starts_with("-mcmodel="))           // -mcmodel=kernel
        return true;
    if (arg.starts_with("-mstack-protector-guard"))
        return true;
    if (arg.starts_with("-fplugin"))            // GCC plugins
        return true;
    if (arg.starts_with("-fdiagnostics-color="))  // GCC-specific color syntax
        return true;

    return false;
}

// Sanitize compile command for Clang IR emission.
// Strips GCC-only flags and adds suppressions for GCC attribute dialects.
std::vector<std::string> sanitizeForClangIR(
        const std::vector<std::string> &args,
        const std::string &srcPath) {
    std::vector<std::string> result;
    result.reserve(args.size() + 2);

    // Suppress warnings about unknown attributes (gnu_printf, etc.)
    // This is cleaner than AST rewriting and achieves the same goal.
    result.push_back("-Wno-unknown-attributes");
    result.push_back("-Wno-ignored-attributes");

    // From 1: args[0] is the compiler path, and passing it on as an input
    // makes clang treat it as an object file.
    for (size_t i = 1; i < args.size(); ++i) {
        const std::string &arg = args[i];

        // Skip -c and -o <file> (we replace these)
        if (arg == "-c")
            continue;
        if (arg == "-o" && i + 1 < args.size()) {
            ++i;
            continue;
        }
        // Skip the source file (we append it at the end)
        if (arg == srcPath)
            continue;

        // --ir-opt is prepended, and clang takes the last -O flag, so the
        // TU's own level would silently win.
        if (arg.size() >= 2 && arg[0] == '-' && arg[1] == 'O' &&
            (arg.size() == 2 || arg == "-O0" || arg == "-O1" ||
             arg == "-O2" || arg == "-O3" || arg == "-Os" || arg == "-Oz" ||
             arg == "-Og" || arg == "-Ofast"))
            continue;

        // Strip GCC-only flags
        if (isGCCOnlyFlag(arg))
            continue;

        // Strip GCC-only flags that take a separate argument
        if (arg == "-mpreferred-stack-boundary" ||
            arg == "-mstack-protector-guard" ||
            arg == "-mstack-protector-guard-reg" ||
            arg == "-mstack-protector-guard-offset") {
            if (i + 1 < args.size())
                ++i;  // skip the argument too
            continue;
        }

        result.push_back(arg);
    }

    return result;
}

struct IRJob {
    std::string srcPath;
    std::string compilerPath;
    std::vector<std::string> argv;
    std::string irFile;
    std::string errFile;
    std::string remarkFile;
    bool cached = false;
};

struct IRResult {
    int exitCode = -1;
    std::string errMsg;
};

IRResult emitOneIR(const IRJob &job) {
    if (job.cached)
        return {0, {}};

    std::vector<llvm::StringRef> argRefs;
    argRefs.reserve(job.argv.size());
    for (const auto &a : job.argv)
        argRefs.push_back(a);

    llvm::StringRef errRedirect(job.errFile);
    std::optional<llvm::StringRef> redirects[] = {
        std::nullopt, std::nullopt, errRedirect
    };

    IRResult result;
    bool failed = false;
    result.exitCode = llvm::sys::ExecuteAndWait(
        job.compilerPath, argRefs,
        /*Env=*/std::nullopt, redirects,
        /*SecondsToWait=*/120, /*MemoryLimit=*/0,
        &result.errMsg, &failed);
    if (failed)
        result.exitCode = -1;
    return result;
}

std::string resolveCompiler(const std::string &dbCompiler) {
    // For IR emission, we MUST use clang (GCC doesn't support -emit-llvm).
    // The dbCompiler from compile_commands.json is only used to check if
    // we should use clang vs clang++ (C vs C++ mode).
    llvm::StringRef stem = llvm::sys::path::stem(dbCompiler);
    bool isCxx = stem.contains("++") || stem.contains("clang++") ||
                 stem.contains("g++") || stem.contains("c++");

    // Try clang/clang++ in order of preference.
    const char *cxxFallbacks[] = {"clang++", "clang++-18", "clang++-17", "clang++-16"};
    const char *cFallbacks[] = {"clang", "clang-18", "clang-17", "clang-16"};
    const char **fallbacks = isCxx ? cxxFallbacks : cFallbacks;
    size_t count = isCxx ? std::size(cxxFallbacks) : std::size(cFallbacks);

    for (size_t i = 0; i < count; ++i) {
        auto fb = llvm::sys::findProgramByName(fallbacks[i]);
        if (fb && llvm::sys::fs::can_execute(*fb))
            return *fb;
    }

    // Last resort: try the other variant
    const char **altFallbacks = isCxx ? cFallbacks : cxxFallbacks;
    size_t altCount = isCxx ? std::size(cFallbacks) : std::size(cxxFallbacks);
    for (size_t i = 0; i < altCount; ++i) {
        auto fb = llvm::sys::findProgramByName(altFallbacks[i]);
        if (fb && llvm::sys::fs::can_execute(*fb))
            return *fb;
    }

    return {};
}

// The shard wire format lives in shard_ipc.cpp. It is plain data on both
// sides and needs no Clang, which is what lets a test link the real
// serializer and the real parser instead of reimplementing the format.

// Address space a shard may map, MiB. Derived from *total* memory, not
// available: available fluctuates with whatever else the box is doing, and a
// cap that moves between runs would make output depend on ambient load.
unsigned resolveShardMemoryLimitMB(unsigned requested, unsigned jobs) {
    if (requested != 0)
        return requested;
    const long pages = ::sysconf(_SC_PHYS_PAGES);
    const long pageSz = ::sysconf(_SC_PAGESIZE);
    if (pages <= 0 || pageSz <= 0)
        return 0; // cannot size it honestly; leave uncapped 
    const unsigned long long totalMB =
        (static_cast<unsigned long long>(pages) * pageSz) >> 20;
    // Leave headroom for the parent and the rest of the machine.
    const unsigned long long share = (totalMB * 3 / 4) / std::max(1u, jobs);
    return static_cast<unsigned>(std::max(2048ULL, share));
}

} // anonymous namespace

// --- Pipeline stages ---

static std::unordered_set<std::string> loadProfileHotFunctions(
        const ScanRequest &req) {
    std::string profilePath = req.perfProfilePath;
    if (profilePath.empty())
        profilePath = req.config.perfProfilePath;
    if (profilePath.empty())
        return {};

    PerfProfileParser parser;
    if (!parser.parse(profilePath))
        return {};

    double threshold = req.hotnessThreshold;
    if (req.config.hotnessThresholdPct > 0 && threshold == 1.0)
        threshold = req.config.hotnessThresholdPct;

    return parser.hotFunctions(threshold);
}

static void runIRPass(
        const ScanRequest &req,
        const clang::tooling::CompilationDatabase &compDB,
        const std::vector<std::string> &sources,
        const std::unordered_set<std::string> &failedFiles,
        std::vector<Diagnostic> &diagnostics,
        ExecutionMetadata &meta,
        std::vector<OptRemark> &remarks,
        unsigned &remarkFilesFailed) {

    IRAnalyzer irAnalyzer;
    std::string optLevel = "-" + req.ir.optLevel;

    std::vector<IRJob> jobs;

    for (const auto &srcPath : sources) {
        // AST-failed TUs already reported; re-driving clang would just
        // duplicate the same errors.
        if (failedFiles.count(srcPath))
            continue;
        auto cmds = compDB.getCompileCommands(srcPath);
        if (cmds.empty())
            continue;

        const std::string &dbCompiler = cmds.front().CommandLine.front();
        std::string compilerPath = resolveCompiler(dbCompiler);
        if (compilerPath.empty())
            continue;

        std::vector<std::string> argv;
        argv.push_back(compilerPath);
        argv.push_back("-S");
        argv.push_back("-emit-llvm");
        argv.push_back("-g");
        argv.push_back(optLevel);

        // Sanitize compile commands: strip GCC-only flags, suppress
        // unknown attribute warnings (gnu_printf, etc.)
        for (const auto &cmd : cmds) {
            auto sanitized = sanitizeForClangIR(cmd.CommandLine, srcPath);
            argv.insert(argv.end(), sanitized.begin(), sanitized.end());
        }

        // Cache key.

        llvm::MD5 hasher;
        auto srcBuf = llvm::MemoryBuffer::getFile(srcPath);
        if (srcBuf)
            hasher.update((*srcBuf)->getBuffer());
        else
            hasher.update(srcPath);

        llvm::sys::fs::file_status srcStat;
        if (!llvm::sys::fs::status(srcPath, srcStat)) {
            auto mtime = srcStat.getLastModificationTime()
                             .time_since_epoch().count();
            hasher.update(llvm::StringRef(
                reinterpret_cast<const char *>(&mtime), sizeof(mtime)));
        }

        llvm::SmallString<256> depPath(srcPath);
        llvm::sys::path::replace_extension(depPath, ".d");
        auto depBuf = llvm::MemoryBuffer::getFile(depPath);
        if (depBuf)
            hasher.update((*depBuf)->getBuffer());

        for (const auto &a : argv)
            hasher.update(a);
        hasher.update(kToolVersion);
        llvm::MD5::MD5Result hashResult;
        hasher.final(hashResult);
        llvm::SmallString<32> hashStr;
        llvm::MD5::stringifyResult(hashResult, hashStr);

        llvm::SmallString<128> tmpDir;
        llvm::sys::path::system_temp_directory(true, tmpDir);
        llvm::SmallString<128> irPath(tmpDir), errPath(tmpDir), remPath(tmpDir);
        llvm::sys::path::append(irPath,
            "lshaz-" + std::string(hashStr) + ".ll");
        llvm::sys::path::append(errPath,
            "lshaz-" + std::string(hashStr) + ".err");
        llvm::sys::path::append(remPath,
            "lshaz-" + std::string(hashStr) + ".opt.yaml");

        // Both artifacts or neither: a hit on the IR alone would silently
        // drop this TU's remarks, so the finding set would depend on what
        // happened to be in /tmp.
        bool cached = req.ir.cacheEnabled && llvm::sys::fs::exists(irPath) &&
                      llvm::sys::fs::exists(remPath);

        argv.push_back("-fsave-optimization-record");
        argv.push_back("-Xclang");
        argv.push_back("-opt-record-passes");
        argv.push_back("-Xclang");
        argv.push_back(remarkPassFilter().str());
        argv.push_back("-foptimization-record-file=" + std::string(remPath));
        argv.push_back("-o");
        argv.push_back(std::string(irPath));
        argv.push_back(srcPath);

        jobs.push_back({srcPath, compilerPath, std::move(argv),
                        std::string(irPath), std::string(errPath),
                        std::string(remPath), cached});

        // Track compilers.
        bool seen = false;
        for (const auto &ci : meta.compilers)
            if (ci.path == compilerPath) { seen = true; break; }
        if (!seen)
            meta.compilers.push_back({compilerPath, {}});
    }

    if (jobs.empty())
        return;

    // Shard-based parallel IR emission.
    unsigned maxWorkers = req.ir.maxJobs;
    if (maxWorkers == 0)
        maxWorkers = std::max(1u, std::thread::hardware_concurrency());
    unsigned batchSize = std::max(1u, req.ir.batchSize);

    struct Shard { size_t begin; size_t end; };
    std::vector<Shard> shards;
    for (size_t i = 0; i < jobs.size(); i += batchSize)
        shards.push_back({i, std::min(i + batchSize, jobs.size())});

    unsigned shardWorkers = std::min(maxWorkers,
                                      static_cast<unsigned>(shards.size()));
    struct ShardResult {
        IRAnalyzer analyzer;
        std::vector<std::pair<size_t, IRResult>> jobResults;
    };

    // A fixed pool pulling shard indices, not a task per shard: at the
    // default batch size of one that is a thread per translation unit, which
    // a large project cannot create. The pool also has no permit to leak when
    // parseIRFile or analyzeModule throws on a bad module.
    std::vector<std::unique_ptr<ShardResult>> results(shards.size());
    std::vector<std::string> shardErrors(shards.size());
    {
        std::atomic<size_t> nextShard{0};
        std::vector<std::thread> pool;
        pool.reserve(shardWorkers);
        for (unsigned w = 0; w < shardWorkers; ++w) {
            pool.emplace_back([&]() {
                for (size_t si = nextShard++; si < shards.size();
                     si = nextShard++) {
                    auto sr = std::make_unique<ShardResult>();
                    try {
                        for (size_t i = shards[si].begin; i < shards[si].end;
                             ++i)
                            sr->jobResults.push_back({i, emitOneIR(jobs[i])});

                        llvm::LLVMContext llvmCtx;
                        for (const auto &[idx, result] : sr->jobResults) {
                            if (result.exitCode != 0)
                                continue;
                            llvm::SMDiagnostic parseErr;
                            auto mod = llvm::parseIRFile(
                                jobs[idx].irFile, parseErr, llvmCtx);
                            if (mod)
                                sr->analyzer.analyzeModule(*mod);
                        }
                    } catch (const std::exception &e) {
                        // Named and counted, not swallowed: the IR pass only
                        // refines AST findings, so losing a shard costs
                        // confidence rather than recall, but a silent loss
                        // reads identically to a shard that found nothing.
                        shardErrors[si] = e.what();
                    }
                    results[si] = std::move(sr);
                }
            });
        }
        for (auto &t : pool)
            t.join();
    }
    for (size_t si = 0; si < shards.size(); ++si) {
        if (!shardErrors[si].empty())
            llvm::errs() << "lshaz: IR shard " << si << " failed: "
                         << shardErrors[si] << " (continuing)\n";
    }

    for (auto &slot : results) {
        auto &sr = *slot;
        for (const auto &[idx, result] : sr.jobResults) {
            if (result.exitCode != 0) {
                auto errBuf = llvm::MemoryBuffer::getFile(jobs[idx].errFile);
                if (errBuf && !(*errBuf)->getBuffer().empty()) {
                    llvm::errs() << "lshaz: IR emission failed for "
                                 << jobs[idx].srcPath << ":\n"
                                 << (*errBuf)->getBuffer() << "\n";
                }
            }
            if (!jobs[idx].cached && result.exitCode != 0) {
                llvm::sys::fs::remove(jobs[idx].irFile);
                llvm::sys::fs::remove(jobs[idx].remarkFile);
            }
            llvm::sys::fs::remove(jobs[idx].errFile);
            // A container that breaks mid-stream keeps what it already
            // yielded, so the count is the only thing that says coverage
            // was partial.
            if (result.exitCode == 0 &&
                !parseOptRemarks(jobs[idx].remarkFile, remarks))
                ++remarkFilesFailed;
        }
        irAnalyzer.mergeFrom(std::move(sr.analyzer));
    }

    // Shards complete in scheduling order, so the stream is ordered here
    // rather than relied on downstream.
    std::sort(remarks.begin(), remarks.end(),
              [](const OptRemark &a, const OptRemark &b) {
                  if (a.file != b.file) return a.file < b.file;
                  if (a.line != b.line) return a.line < b.line;
                  if (a.column != b.column) return a.column < b.column;
                  if (a.name != b.name) return a.name < b.name;
                  return a.function < b.function;
              });

    if (!irAnalyzer.profiles().empty()) {
        DiagnosticRefiner refiner(irAnalyzer.profiles(),
                                  req.config.stackFrameWarnBytes);
        refiner.refine(diagnostics);
    }
}

static unsigned applyCalibrationSuppression(
        std::vector<Diagnostic> &diagnostics,
        CalibrationFeedbackStore &store) {
    unsigned suppressed = 0;
    diagnostics.erase(
        std::remove_if(diagnostics.begin(), diagnostics.end(),
                       [&](const Diagnostic &d) {
                           auto hc = HypothesisConstructor
                               ::mapRuleToHazardClass(d.ruleID);
                           auto features = HypothesisConstructor
                               ::extractFeatures(d);
                           bool highSev =
                               d.severity == Severity::Critical ||
                               d.severity == Severity::High;
                           bool proven =
                               d.evidenceTier == EvidenceTier::Proven;
                           if (highSev && proven)
                               return false;
                           if (store.isKnownFalsePositive(features, hc)) {
                               ++suppressed;
                               return true;
                           }
                           return false;
                       }),
        diagnostics.end());
    return suppressed;
}

static void applyPMUFeedback(
        const FeedbackOptions &fb,
        std::vector<Diagnostic> &diagnostics,
        CalibrationFeedbackStore &store) {
    PMUTraceFeedbackLoop feedbackLoop(store);

    if (!fb.pmuPriorsPath.empty())
        feedbackLoop.loadPriors(fb.pmuPriorsPath);

    if (!fb.pmuTracePath.empty()) {
        auto traceBuf = llvm::MemoryBuffer::getFile(fb.pmuTracePath);
        if (traceBuf) {
            llvm::StringRef data = (*traceBuf)->getBuffer();
            llvm::SmallVector<llvm::StringRef, 0> lines;
            data.split(lines, '\n', -1, false);

            PMUTraceRecord currentRecord;
            auto flushRecord = [&]() {
                if (currentRecord.functionName.empty())
                    return;
                for (const auto &d : diagnostics) {
                    if (d.functionName == currentRecord.functionName ||
                        (d.location.file == currentRecord.sourceFile &&
                         d.location.line == currentRecord.sourceLine)) {
                        auto hc = HypothesisConstructor
                            ::mapRuleToHazardClass(d.ruleID);
                        auto features = HypothesisConstructor
                            ::extractFeatures(d);
                        feedbackLoop.ingestTrace(currentRecord, hc, features);
                        break;
                    }
                }
            };

            for (const auto &line : lines) {
                if (line.starts_with("#"))
                    continue;

                llvm::SmallVector<llvm::StringRef, 6> fields;
                line.split(fields, '\t');
                if (fields.size() < 5)
                    continue;

                std::string func = fields[0].str();
                std::string file = fields[1].str();
                unsigned srcLine = 0;
                fields[2].getAsInteger(10, srcLine);

                if (!currentRecord.functionName.empty() &&
                    (currentRecord.functionName != func ||
                     currentRecord.sourceLine != srcLine)) {
                    flushRecord();
                    currentRecord = {};
                }

                currentRecord.functionName = func;
                currentRecord.sourceFile = file;
                currentRecord.sourceLine = srcLine;

                PMUSample sample;
                sample.counterName = fields[3].str();
                fields[4].getAsInteger(10, sample.value);
                if (fields.size() > 5)
                    fields[5].getAsInteger(10, sample.duration_ns);
                currentRecord.samples.push_back(std::move(sample));
            }
            flushRecord();
        }
    }

    for (auto &d : diagnostics) {
        auto hc = HypothesisConstructor::mapRuleToHazardClass(d.ruleID);
        d.confidence = feedbackLoop.adjustConfidence(d.confidence, hc);
    }

    if (!fb.pmuPriorsPath.empty())
        feedbackLoop.savePriors(fb.pmuPriorsPath);
}

// Cross-TU thread-role escalation. FL002 joins at pair granularity through
// its pair_fields evidence; FL090's claim is struct-wide, so any two
// attributed fields with disjoint roles evidence its concurrency assumption.
//
// Confidence only, never severity: that leaves the deliberate-layout demotion
// intact, and a demoted struct whose flagged pair still attributes to
// disjoint threads is exactly the "mitigation missed this pair" signal.
static const char *roleMaskName(uint8_t mask) {
    switch (mask) {
        case ROLE_MAIN:   return "main-thread";
        case ROLE_WORKER: return "worker-thread";
        default:          return "mixed-role";
    }
}

static unsigned applyThreadRoleEscalation(
        std::vector<Diagnostic> &diagnostics,
        const ThreadRoleSummary &facts,
        const ThreadRoleVerdicts &verdicts) {
    if (verdicts.functionRoles.empty())
        return 0;

    unsigned escalated = 0;
    for (auto &d : diagnostics) {
        if (d.suppressed)
            continue;
        if (d.ruleID != "FL002" && d.ruleID != "FL090")
            continue;
        auto tit = d.structuralEvidence.find("type_name");
        if (tit == d.structuralEvidence.end() || tit->second.empty())
            continue;
        const std::string &type = tit->second;

        std::string fieldA, fieldB;
        if (d.ruleID == "FL002") {
            auto pit = d.structuralEvidence.find("pair_fields");
            if (pit == d.structuralEvidence.end())
                continue;
            // "a|b;c|d" - first disjoint pair in flagged order wins.
            const std::string &pf = pit->second;
            size_t pos = 0;
            while (pos < pf.size() && fieldA.empty()) {
                size_t semi = pf.find(';', pos);
                std::string pair = pf.substr(pos, semi == std::string::npos
                                                      ? std::string::npos
                                                      : semi - pos);
                size_t bar = pair.find('|');
                if (bar != std::string::npos) {
                    std::string a = pair.substr(0, bar);
                    std::string b = pair.substr(bar + 1);
                    if (verdicts.fieldsHaveDisjointWriterRoles(
                            facts, type + "::" + a, type + "::" + b)) {
                        fieldA = a;
                        fieldB = b;
                    }
                }
                if (semi == std::string::npos)
                    break;
                pos = semi + 1;
            }
        } else {
            // FL090: first (lexicographic, via ordered map) disjoint pair
            // among the type's attributed fields.
            const std::string prefix = type + "::";
            std::vector<std::pair<std::string, uint8_t>> attributed;
            for (auto it = facts.fieldWriters.lower_bound(prefix);
                 it != facts.fieldWriters.end() &&
                 it->first.compare(0, prefix.size(), prefix) == 0;
                 ++it) {
                uint8_t mask = verdicts.fieldWriterRoles(facts, it->first);
                if (mask != ROLE_NONE)
                    attributed.emplace_back(
                        it->first.substr(prefix.size()), mask);
            }
            for (size_t i = 0; i < attributed.size() && fieldA.empty(); ++i)
                for (size_t j = i + 1; j < attributed.size(); ++j)
                    if ((attributed[i].second & attributed[j].second) == 0) {
                        fieldA = attributed[i].first;
                        fieldB = attributed[j].first;
                        break;
                    }
        }
        if (fieldA.empty())
            continue;

        uint8_t ra = verdicts.fieldWriterRoles(facts, type + "::" + fieldA);
        uint8_t rb = verdicts.fieldWriterRoles(facts, type + "::" + fieldB);
        // The merged graph settles what the per-TU pass could only assume.
        // Rewarding it numerically as well would score one cause twice: the
        // rule's own writer evidence already counted it.
        d.settleClaim("MESI invalidation ping-pong", ClaimState::Established,
                      "writers of '" + fieldA + "' and '" + fieldB +
                      "' attribute to disjoint thread roles");
        d.escalations.push_back(
            "cross-TU thread-role attribution: '" + fieldA +
            "' written only from " + roleMaskName(ra) + " code, '" + fieldB +
            "' only from " + roleMaskName(rb) +
            " code. Concurrent cross-thread writes evidenced, not assumed");
        ++escalated;
    }
    return escalated;
}

// FL060 first-touch heuristics assume nobody is managing placement. A
// codebase calling affinity/mempolicy APIs has an author doing exactly
// that; the same respect contract deliberate layout earns from FL002.
// Reduce-side only: the merged call edges already carry every direct
// callee name.
static std::string detectAffinityManagement(const ThreadRoleSummary &facts) {
    static const char *kAPIs[] = {
        "pthread_setaffinity_np", "sched_setaffinity", "mbind",
        "set_mempolicy",          "numa_bind",         "numa_run_on_node",
        "numa_set_membind",       "numa_alloc_onnode", "numa_tonode_memory",
    };
    // Ordered facts + fixed API order = deterministic first match.
    for (const char *api : kAPIs)
        for (const auto &[caller, callees] : facts.callEdges)
            if (callees.count(api))
                return api;
    return {};
}

// Same contract for FL070: in-tree madvise/mallopt means the author
// already manages paging policy.
static bool detectPagingManagement(const ThreadRoleSummary &facts) {
    for (const auto &[caller, callees] : facts.callEdges)
        if (callees.count("madvise") || callees.count("posix_madvise") ||
            callees.count("mallopt"))
            return true;
    return false;
}

static unsigned applyPagingRespect(std::vector<Diagnostic> &diagnostics,
                                   bool managed) {
    if (!managed)
        return 0;
    unsigned demoted = 0;
    for (auto &d : diagnostics) {
        if (d.suppressed || d.ruleID != "FL070")
            continue;
        // Severity is the axis this belongs on. An author steering paging
        // changes what the hazard costs, not how well we identified it.
        d.severity = Severity::Informational;
        d.escalations.push_back(
            "paging policy managed in-tree (madvise/mallopt observed): "
            "hugepage inference demoted, verify against the author's "
            "policy");
        ++demoted;
    }
    return demoted;
}

static unsigned applyAffinityRespect(std::vector<Diagnostic> &diagnostics,
                                     const std::string &api) {
    if (api.empty())
        return 0;
    unsigned demoted = 0;
    for (auto &d : diagnostics) {
        if (d.suppressed || d.ruleID != "FL060")
            continue;
        if (d.severity == Severity::Critical)
            d.severity = Severity::High;
        else if (d.severity == Severity::High)
            d.severity = Severity::Medium;
        else
            d.severity = Severity::Informational;
        d.escalations.push_back(
            "explicit placement management in-tree (" + api +
            "): first-touch inference demoted. The author is already "
            "steering affinity; verify against their policy, not the "
            "default model");
        ++demoted;
    }
    return demoted;
}

// FL003: per-thread striped arrays. slots pack floor(line/elemSize) per
// line; slots i and j written by different cores trade the line in
// Modified state every update. emitted in reduce because the writer-role
// join only exists post-merge.
static unsigned emitStripedArrayFindings(
        std::vector<Diagnostic> &diagnostics,
        const StripedArraySummary &striped,
        const ThreadRoleVerdicts &roles,
        uint64_t lineBytes, uint64_t l1dSizeBytes,
        bool alignedOwnerAvailable) {
    unsigned emitted = 0;
    for (const auto &[key, s] : striped) {
        if (s.stripedWriters.empty())
            continue;  // no thread-indexed write observed: not striping
        StripeVerdict v = gradeStripedArray(s, roles, lineBytes);
        if (v.mitigation == StripeMitigation::FullyPadded)
            continue;
        if (v.slotsPerLine < 2)
            continue;
        // Packed slots that no two cores ever write. The role join has to be
        // consulted in the direction that lowers severity as well as the one
        // that raises it, or a thread-identity subscript alone carries High.
        if (v.mainThreadOnly)
            continue;
        applyStripeROI(v, s, lineBytes, l1dSizeBytes, alignedOwnerAvailable);

        Diagnostic d;
        d.ruleID = "FL003";
        d.title = "Per-Thread Array False Sharing";
        // confidence answers "is the hazard real", severity answers "is it
        // worth acting on". a thread-identity subscript is itself evidence
        // the writer runs on several threads; the role join only confirms
        // it, and event-loop dispatch hides that path.
        if (v.multiRole) {
            d.confidence = 0.88;
            d.evidenceTier = EvidenceTier::Proven;
        } else if (s.tlsIndexed || v.writerCount >= 2 || s.elementIsAtomic) {
            d.confidence = s.tlsIndexed ? 0.78 : 0.72;
            d.evidenceTier = EvidenceTier::Likely;
        } else {
            d.confidence = 0.55;
            d.evidenceTier = EvidenceTier::Likely;
        }

        // a hazard whose only available fix costs more than it saves is
        // not an action item, however certain the mechanism is.
        if (v.fixShape == StripeFixShape::None) {
            d.severity = Severity::Informational;
        } else if (v.frequency == WriteFrequencyTier::Hot) {
            d.severity = v.multiRole ? Severity::Critical : Severity::High;
        } else if (v.frequency == WriteFrequencyTier::Unknown) {
            // unestablished is not low: demoting here would be the same
            // error as reading an unprovable flag as proven-absent.
            d.severity = v.multiRole ? Severity::Critical
                       : (s.tlsIndexed || v.writerCount >= 2 ||
                          s.elementIsAtomic) ? Severity::High
                                             : Severity::Medium;
            d.escalations.push_back(
                "write frequency unestablished: no hot-path signal reaches "
                "these writers, supply hot_function_patterns or "
                "--perf-profile to grade the fix against real call rate");
        } else {
            d.severity = Severity::Medium;
        }
        // aligned base + padded index origin is deliberate line-aware
        // layout: cap like the other mitigation-respect contracts. the
        // residual (slots 1.. still pack) is stated, not escalated.
        if (v.mitigation == StripeMitigation::HeadPadded &&
            d.severity > Severity::Medium)
            d.severity = Severity::Medium;
        // Demoted, not dropped: a worker that stamps itself into the object
        // first makes the owner id its own, undecidable here. Where the role
        // join already settled it, the grade stands.
        if (v.ownerIndexed && !v.multiRole) {
            if (d.severity > Severity::Medium)
                d.severity = Severity::Medium;
            d.escalations.push_back(
                "every thread-identity subscript reaches this array through a "
                "field of an object the caller handed in, which names the "
                "object's owner rather than the writing thread: one thread "
                "can drive every slot, so striping is not established");
        }

        d.location.file = s.file;
        d.location.line = s.line;
        d.location.column = 1;

        const bool straddles =
            strideStraddlesLines(s.elemSizeBytes, lineBytes) &&
            s.elemSizeBytes > lineBytes;
        std::ostringstream hw;
        hw << (s.isFileStatic ? "Static array '" : "Array '") << s.displayName;
        if (straddles)
            hw << "' has a " << s.elemSizeBytes << "B stride that is not a "
               << "multiple of the " << lineBytes << "B line, so element "
               << "boundaries fall mid-line whatever the base address is: "
               << v.contendedLines << " boundary line(s) across "
               << s.elemCount << " slots are each written by the pair of "
               << "elements that meet there.";
        else
            hw << "' packs " << v.slotsPerLine << " slots per " << lineBytes
               << "B line across " << v.contendedLines << " line(s) ("
               << s.elemCount << " x " << s.elemSizeBytes << "B).";
        hw << " Slots are written under a thread-identity index, so distinct "
           << "cores update distinct slots on the same line: every write "
           << "takes the line in Modified state and invalidates it in the "
           << "other core.";
        if (!s.elementIsAtomic)
            hw << " Elements are non-atomic, striping makes each slot "
                  "single-writer, so this is coherence traffic without a "
                  "data race.";
        d.hardwareReasoning = hw.str();

        d.structuralEvidence = {
            {"symbol", s.displayName},
            {"elem_size", std::to_string(s.elemSizeBytes)},
            {"elem_count", std::to_string(s.elemCount)},
            {"slots_per_line", std::to_string(v.slotsPerLine)},
            {"contended_lines", std::to_string(v.contendedLines)},
            {"striped_writers", std::to_string(v.writerCount)},
            {"tls_indexed", s.tlsIndexed ? "yes" : "no"},
            {"index_identity", v.ownerIndexed ? "owner" : "writer"},
            {"atomic_elem", s.elementIsAtomic ? "yes" : "no"},
            {"scope", s.isFileStatic ? "file-static" : "member"},
            {"write_frequency", writeFrequencyName(v.frequency)},
            {"fix_shape", stripeFixName(v.fixShape)},
            {"footprint_current", std::to_string(v.currentFootprint)},
            {"footprint_padded", std::to_string(v.paddedFootprint)},
            {"l1d_cost_pct",
             std::to_string(static_cast<int>(v.l1dCostFraction * 100))},
        };
        if (!s.typeName.empty())
            d.structuralEvidence["type_name"] = s.typeName;

        for (const auto &w : s.stripedWriters)
            d.escalations.push_back("thread-indexed write from '" + w + "'");
        for (const auto &g : s.aggregators)
            d.escalations.push_back("loop-swept aggregation in '" + g +
                                    "' (read side, not a striped write)");
        if (v.mitigation == StripeMitigation::HeadPadded)
            d.escalations.push_back(
                "base is line-aligned with a padded index origin: slot 0 is "
                "isolated, slots 1.. still share lines");

        // Striping guarantees single-writer-per-slot, so atomicity is not
        // what establishes contention here, index provenance and distinct
        // writers are. The write-frequency tier is the other precondition:
        // unestablished it must not carry the top grade, which is the same
        // discipline FL040 and FL011 now follow.
        d.mechanismClaims = {
            {"several thread slots share one cache line",
             straddles ? "an element stride that is not a line multiple, so "
                         "boundaries fall mid-line for any base address"
                       : "an element stride narrower than the line, unpadded",
             ClaimState::Established, Severity::Medium},
            {"per-write RFO transfer between the owning cores",
             "distinct thread-indexed writers reaching separate slots",
             claimFrom(v.writerCount >= 2 || s.tlsIndexed),
             v.multiRole ? Severity::Critical : Severity::High},
            {"the traffic is sustained at hot-path rates",
             "writes established on a hot path rather than assumed",
             claimFrom(v.frequency == WriteFrequencyTier::Hot),
             Severity::Critical},
        };

        {
            std::ostringstream mit;
            switch (v.fixShape) {
            case StripeFixShape::FullPad:
                mit << "Give each slot its own line (alignas(" << lineBytes
                    << ") element wrapper): " << v.currentFootprint << "B -> "
                    << v.paddedFootprint << "B, "
                    << static_cast<int>(v.l1dCostFraction * 100)
                    << "% of L1D. " << v.fixRationale << ".";
                break;
            case StripeFixShape::RelocateToOwner:
                mit << "Move the slot into the existing line-aligned "
                       "per-thread structure rather than padding this array: "
                    << v.fixRationale << ". Full padding would cost "
                    << static_cast<int>(v.l1dCostFraction * 100)
                    << "% of L1D for no additional isolation.";
                break;
            case StripeFixShape::HeadPad:
                mit << "Align the base and start indexing at a padded origin "
                       "to isolate the hottest slot: " << v.fixRationale
                    << ". Full padding would cost "
                    << static_cast<int>(v.l1dCostFraction * 100)
                    << "% of L1D.";
                break;
            case StripeFixShape::None:
                mit << "No worthwhile fix: " << v.fixRationale
                    << " (full padding " << v.currentFootprint << "B -> "
                    << v.paddedFootprint << "B = "
                    << static_cast<int>(v.l1dCostFraction * 100)
                    << "% of L1D). Re-evaluate if this write moves onto a "
                       "per-command path.";
                break;
            }
            d.mitigation = mit.str();
        }
        diagnostics.push_back(std::move(d));
        ++emitted;
    }
    return emitted;
}

// FL004: a loop reading every per-thread slot takes each one in Shared,
// downgrading its owner out of Modified and costing that owner an Exclusive
// re-acquire on its next write. Padding cannot fix it and increases the line
// count, so the correctly padded array FL003 skips is where this lives.
static constexpr const char *kSweepMechanism = "coherence_sweep";

// Which call sites the estimate was built from, in a form a profile can be
// joined against. The number is a claim about these functions specifically,
// so a measurement naming none of them has not tested it, and one naming a
// different set measured something else. Sets are ordered, so the rendering
// is too.
static void recordCostSites(Diagnostic &d,
                            const std::set<std::string> &writers,
                            const std::set<std::string> &readers) {
    const auto join = [](const std::set<std::string> &s) {
        std::string out;
        for (const auto &n : s) {
            if (!out.empty()) out += ',';
            out += n;
        }
        return out;
    };
    if (!writers.empty()) d.structuralEvidence["cost_writers"] = join(writers);
    if (!readers.empty()) d.structuralEvidence["cost_readers"] = join(readers);
}

static unsigned emitAggregationSweepFindings(
        std::vector<Diagnostic> &diagnostics,
        const StripedArraySummary &striped,
        const ThreadRoleVerdicts &roles,
        const RateModel &rates,
        const MachineModel &machine,
        const CostCalibration &calib,
        const std::string &workloadName,
        const WorkloadModel &workload,
        uint64_t lineBytes) {
    // Below this the sweep touches a couple of lines and no call rate
    // makes that matter.
    constexpr uint64_t kMinSweptLines = 4;
    unsigned emitted = 0;
    for (const auto &[key, s] : striped) {
        if (s.aggregators.empty()) continue;
        // No writer means no line is ever in Modified state, so the sweep
        // costs nothing to downgrade.
        if (s.stripedWriters.empty()) continue;
        if (lineBytes == 0 || s.elemSizeBytes == 0 || s.elemCount == 0)
            continue;

        StripeVerdict v = gradeStripedArray(s, roles, lineBytes);
        // Every writer on one thread means no line is ever owned elsewhere.
        if (v.mainThreadOnly) continue;

        const uint64_t bytes = s.elemCount * s.elemSizeBytes;
        const uint64_t sweptLines = (bytes + lineBytes - 1) / lineBytes;
        if (sweptLines < kMinSweptLines) continue;

        const auto tier = static_cast<WriteFrequencyTier>(s.aggregatorTier);
        Diagnostic d;
        d.ruleID = "FL004";
        d.title = "Aggregation Sweep Over Per-Thread Slots";
        d.location.file = s.file;
        d.location.line = s.line;
        d.location.column = 1;
        d.confidence = v.multiRole ? 0.85 : 0.70;
        d.evidenceTier = v.multiRole ? EvidenceTier::Proven
                                     : EvidenceTier::Likely;

        // Sweeping on a stats timer is the correct design, so tick must not
        // grade as a hazard however many lines it covers.
        if (tier == WriteFrequencyTier::Hot)
            d.severity = sweptLines >= 16 ? Severity::Critical : Severity::High;
        else if (tier == WriteFrequencyTier::Dispatch)
            d.severity = Severity::Medium;
        else if (tier == WriteFrequencyTier::Tick)
            d.severity = Severity::Informational;
        else {
            d.severity = Severity::Medium;
            d.escalations.push_back(
                "sweep frequency unestablished: no hot-path signal reaches "
                "these readers, so the cost per call is known and the call "
                "rate is not");
        }

        std::ostringstream hw;
        hw << "'" << s.displayName << "' is swept by " << s.aggregators.size()
           << " loop(s) over as many as " << s.elemCount
           << " slots spanning up to " << sweptLines << " cache line(s), "
           << "while " << v.writerCount
           << " thread-identity writer(s) own those slots. "
           << "Reading a slot takes its line in Shared and downgrades the "
           << "owning core from Modified; that owner then pays an Exclusive "
           << "re-acquire on its next write, so the sweep costs about "
           << (2 * sweptLines) << " coherence transactions per call. That "
           << "count is the declared bound and an upper bound on it: a loop "
           << "that stops at a configured thread count touches "
           << "proportionally fewer lines. Padding the slots apart does not "
           << "reduce any of it, since separating the writers from each "
           << "other does nothing about a reader that touches every line.";
        d.hardwareReasoning = hw.str();

        d.structuralEvidence = {
            {"symbol", s.displayName},
            {"elem_count", std::to_string(s.elemCount)},
            {"elem_size", std::to_string(s.elemSizeBytes)},
            {"swept_lines_max", std::to_string(sweptLines)},
            {"transactions_per_sweep_max", std::to_string(2 * sweptLines)},
            {"sweep_frequency", writeFrequencyName(tier)},
            {"sweepers", std::to_string(s.aggregators.size())},
            {"striped_writers", std::to_string(v.writerCount)},
            {"slots_padded_apart",
             classifyStripeMitigation(s, lineBytes) ==
                     StripeMitigation::FullyPadded ? "yes" : "no"},
        };
        if (!s.typeName.empty())
            d.structuralEvidence["type_name"] = s.typeName;
        for (const auto &g : s.aggregators)
            d.escalations.push_back("sweeps every slot in '" + g + "'");

        d.mechanismClaims = {
            {"each swept slot's line is taken in Shared, downgrading its "
             "owner out of Modified",
             "a loop reads every slot of an array written under a "
             "thread-identity index", ClaimState::Established, Severity::Medium},
            {"the owner pays an Exclusive re-acquire on its next write",
             "writers observed on the swept array",
             claimFrom(v.writerCount >= 1),
             Severity::High},
            {"the sweep runs often enough for the cost to recur",
             "sweep hotness established rather than assumed",
             claimFrom(tier == WriteFrequencyTier::Hot), Severity::Critical},
        };

        d.mitigation =
            "Keep a running total the writers update, or cache the aggregate "
            "and refresh it off the hot path. Sweeping is correct on a stats "
            "timer and wrong per operation, and no amount of padding changes "
            "that: the cost is the number of lines touched, which padding "
            "increases. If the sweep genuinely must be live, read it from "
            "one thread and publish the result.";

        // Costed with the same machinery as a shared line, because it is the
        // same event counted differently: the sweep's own rate against two
        // transactions per line it touches. A distinct mechanism name keeps
        // its residual separate, since a sweep's misses are sequential and
        // prefetchable where a contended field's are not, and one correction
        // must not be learned from the other.
        {
            CostEstimate est;
            est.mechanism = kSweepMechanism;
            const bool rateKnown = rates.anyKnown(s.aggregators);
            const Milli sweepRate =
                rateKnown ? rates.maxRateOf(s.aggregators) : kMilli;
            est.add("sweep_rate", sweepRate, rateKnown,
                    rateKnown ? "call graph"
                              : "unmeasured, taken as once per op");
            // A deployment with one sharer sweeps its own lines and nothing
            // is ever held elsewhere, so there is nothing to downgrade.
            // Same correction as the shared-line expression: a sweep on a
            // deployment where nothing else holds the lines downgrades
            // nobody.
            if (workload.sharersKnown())
                est.add("sharers",
                        toMilli(workload.sharers > 1 ? 1 : 0), true,
                        workload.sharers > 1
                            ? "workload_sharers shows the lines are held "
                              "elsewhere"
                            : "workload_sharers is 1: no line is held "
                              "elsewhere");
            est.add("transactions",
                    toMilli(static_cast<int64_t>(2 * sweptLines)), true,
                    "two per line swept: Shared on the read, Exclusive on the "
                    "owner's next write");
            est.add("hitm_cycles",
                    toMilli(machine.cyclesHitmLocal ? machine.cyclesHitmLocal
                                                    : 100),
                    machine.hasCoherenceCost(),
                    machine.hasCoherenceCost() ? machine.name
                                               : "unmeasured, taken as 100",
                    TermRole::Conversion);
            const Milli exposed =
                machine.hasOverlap()
                    ? toMilli(100 - static_cast<int64_t>(machine.mlpOverlapPct)) / 100
                    : kMilli;
            est.add("exposed_share", exposed, machine.hasOverlap(),
                    machine.hasOverlap() ? machine.name
                                         : "unmeasured, taken as fully exposed",
                    TermRole::Conversion);
            if (auto f = calib.factorFor(kSweepMechanism, machine.name,
                                         workloadName)) {
                const bool trusted =
                    f->samples >= CostCalibration::kTrustedSamples;
                est.add("calibration", f->value, trusted,
                        std::to_string(f->samples) + " observation(s) on " +
                            machine.name + "/" + workloadName +
                            (trusted ? "" : ", below the trusted sample count"),
                        TermRole::Correction);
            }
            est.settle();
            d.cost = est;
            recordCostSites(d, {}, s.aggregators);
        }

        diagnostics.push_back(std::move(d));
        ++emitted;
    }
    return emitted;
}

// A store in a function reached once from main runs once, and no per-TU view
// can tell that from one reached per command. FL005 ships its repetition
// claim unestablished for exactly that reason; this settles it against the
// merged graph and drops the finding where the store provably runs once.
static unsigned settleStoreRepetition(std::vector<Diagnostic> &diagnostics,
                                      const ThreadRoleSummary &facts) {
    // Callers per callee, and whether any of those edges sits in a loop.
    std::map<std::string, unsigned> callers;
    std::set<std::string> loopReached;
    for (const auto &[caller, callees] : facts.callEdges)
        for (const auto &callee : callees)
            ++callers[callee];
    for (const auto &[caller, edges] : facts.edgeLoopDepth)
        for (const auto &[callee, depth] : edges)
            if (depth > 0)
                loopReached.insert(callee);

    unsigned settled = 0, dropped = 0;
    for (auto &d : diagnostics) {
        if (d.suppressed || d.ruleID != "FL005")
            continue;
        auto it = d.structuralEvidence.find("store_function");
        if (it == d.structuralEvidence.end())
            continue;
        const std::string &fn = it->second;
        auto c = callers.find(fn);
        const unsigned nCallers = c == callers.end() ? 0 : c->second;
        const bool repeats = loopReached.count(fn) || nCallers >= 2;
        // Absent from the graph means unanalysed, not proven single-shot: an
        // entry point or a function only reached through a pointer table has
        // no recorded caller and may well run per operation.
        // main is the one function whose absence from the callee map means
        // it runs once rather than that nothing recorded a caller.
        const bool provablyOnce =
            !loopReached.count(fn) && (nCallers == 1 || fn == "main");
        if (provablyOnce) {
            d.suppressed = true;
            ++dropped;
            continue;
        }
        for (auto &claim : d.mechanismClaims)
            if (claim.gating && claim.effect == "the store runs more than once")
                claim.state = claimFrom(repeats);
        if (repeats) {
            d.escalations.push_back(
                "the store repeats: '" + fn + "' is reached from " +
                std::to_string(nCallers) + " call site(s)" +
                (loopReached.count(fn) ? ", at least one inside a loop" : ""));
            ++settled;
        } else {
            d.escalations.push_back(
                "no call edge to '" + fn + "' was recorded, so how often the "
                "store runs is unknown rather than established");
        }
    }
    return dropped * 1000u + settled;
}

// What a shared line costs per unit of the target's work.
//
//   transfers/op = write_rate * sharers * min(1, read_rate/write_rate)
//   cycles/op    = transfers * hitm_cycles * (1 - overlap)
//
// The rate ratio stops this charging every store to every core: a store
// only costs a sharer that reads before the next store lands. The overlap
// term is why a coherence finding measures zero on a syscall-bound server,
// where the miss hides behind work already in flight.
//
// Every unestablished term takes its cost-maximising value, never a middle
// guess. That is what makes a low product a sound dismissal and a high one
// merely unproven.
static constexpr const char *kCoherenceMechanism = "coherence_line_sharing";

static CostEstimate estimateLineCost(const std::set<std::string> &writers,
                                     const std::set<std::string> &readers,
                                     bool disjointRoles,
                                     const RateModel &rates,
                                     const MachineModel &machine,
                                     const CostCalibration &calib,
                                     const std::string &workloadName,
                                     const WorkloadModel &workload,
                                     const std::string &site = {},
                                     const char *mechanism =
                                         kCoherenceMechanism) {
    CostEstimate est;
    est.mechanism = mechanism;
    est.site = site;

    const bool wKnown = rates.anyKnown(writers);
    const Milli wRate = wKnown ? rates.maxRateOf(writers) : kMilli;
    est.add("write_rate", wRate, wKnown,
            wKnown ? "call graph" : "unmeasured, taken as once per op");

    // Total read rate, not the busiest reader's. A line read once per
    // operation from forty places on the command path is re-fetched far more
    // often than one read from two, and a maximum prices both the same.
    //
    // Saturating at once per operation, because a rate model built on four
    // loop-depth buckets cannot defend a claim above that, and an unbounded
    // sum over a large reader set would run away on exactly the fields where
    // the buckets are least trustworthy.
    const bool rKnown = rates.anyKnown(readers);
    Milli rSum = 0;
    for (const auto &fn : readers) {
        rSum += rates.rateOf(fn);
        if (rSum >= kMilli) { rSum = kMilli; break; }
    }
    const Milli rRate = rKnown ? rSum : kMilli;

    // Cores that pay, one fewer than the cores that touch the line: the
    // store's own core does not invalidate itself, so a single-sharer
    // deployment prices to zero.
    //
    // Source cannot count sharers. The thread-entry count is how many bodies
    // exist, not how many run at once on this object, so a configured count
    // beats any inference and disjoint writer/reader roles prove two.
    const auto payers = [](int64_t touching) {
        return toMilli(touching > 1 ? touching - 1 : 0);
    };
    if (workload.sharersKnown())
        est.add("sharers", payers(workload.sharers), true,
                "workload_sharers minus the storing core");
    else
        est.add("sharers", payers(disjointRoles ? 2 : 4), disjointRoles,
                disjointRoles ? "writer and reader roles are disjoint"
                              : "not established, taken as 4");

    Milli ratio = kMilli;
    if (wRate > 0 && rRate < wRate)
        ratio = static_cast<Milli>(
            (static_cast<__int128>(rRate) * kMilli) / wRate);
    est.add("reads_per_store", ratio, wKnown && rKnown, "call graph");

    est.add("hitm_cycles",
            toMilli(machine.cyclesHitmLocal ? machine.cyclesHitmLocal : 100),
            machine.hasCoherenceCost(),
            machine.hasCoherenceCost() ? machine.name
                                       : "unmeasured, taken as 100",
            TermRole::Conversion);

    const Milli exposed =
        machine.hasOverlap()
            ? toMilli(100 - static_cast<int64_t>(machine.mlpOverlapPct)) / 100
            : kMilli;
    est.add("exposed_share", exposed, machine.hasOverlap(),
            machine.hasOverlap() ? machine.name
                                 : "unmeasured, taken as fully exposed",
            TermRole::Conversion);

    // What measurement has said, about this line if anything has measured
    // it and about the mechanism otherwise. Absent means nobody has checked,
    // and no term is added: a neutral factor of one that looked established
    // would claim the model had been verified here when it has not.
    //
    // A sited factor is the only thing separating two lines the static model
    // prices identically, and it prices them identically for a sound reason:
    // coherence cost is stores per operation times the cores holding the
    // line, reads do not multiply it, and how often a line is actually
    // stored per operation is a property of the run.
    if (auto f = calib.factorFor(est.mechanism, machine.name,
                                 workloadName, site)) {
        const bool trusted = f->samples >= CostCalibration::kTrustedSamples;
        est.add("calibration", f->value, trusted,
                std::to_string(f->samples) + " observation(s) on " +
                    machine.name + "/" + workloadName +
                    (f->sited ? " of " + site : " of this mechanism") +
                    (trusted ? "" : ", below the trusted sample count"),
                TermRole::Correction);
    }

    est.settle();
    return est;
}


// The estimate enters the ledger as a gating claim, which is where a
// conjunct belongs. It can retire a finding the structure graded Critical,
// because a cost built from cost-maximising stand-ins that still lands below
// the threshold is a sound dismissal. It cannot promote one: an estimate
// with any unmeasured term supports no more than the finding already had.
static unsigned applyCostVerdict(std::vector<Diagnostic> &diagnostics,
                                 const ThreadRoleSummary &facts,
                                 const ThreadRoleVerdicts &roles,
                                 const RateModel &rates,
                                 const MachineModel &machine,
                                 const WorkloadModel &workload,
                                 const CostCalibration &calib,
                                 const std::string &workloadName) {
    unsigned graded = 0;
    for (auto &d : diagnostics) {
        if (d.suppressed)
            continue;
        // Every line-sharing finding gets costed, not only the ones the
        // cross-TU join built: the pair the rule already flagged carries the
        // field names, and the merged facts carry who touches them.
        if (d.cost.empty() && (d.ruleID == "FL002" || d.ruleID == "FL041")) {
            auto tn = d.structuralEvidence.find("type_name");
            auto pf = d.structuralEvidence.find("pair_fields");
            if (tn != d.structuralEvidence.end() &&
                pf != d.structuralEvidence.end() && !pf->second.empty()) {
                // Every pair on the list, not the first one. A finding
                // describes as many lines as it lists pairs and its cost is
                // the worst of them; the list is in the rule's enumeration
                // order, which says nothing about cost.
                static const std::set<std::string> kNone;
                const auto setFor =
                    [&](const std::map<std::string, std::set<std::string>> &m,
                        const std::string &k) -> const std::set<std::string> & {
                    auto it = m.find(k);
                    return it != m.end() ? it->second : kNone;
                };
                const std::set<std::string> *bestW = nullptr, *bestR = nullptr;
                CostEstimate best;
                const std::string &pairs = pf->second;
                size_t start = 0;
                while (start < pairs.size()) {
                    const auto semi = pairs.find(';', start);
                    const auto end =
                        semi == std::string::npos ? pairs.size() : semi;
                    const std::string pair = pairs.substr(start, end - start);
                    start = end + 1;
                    const size_t bar = pair.find('|');
                    if (bar == std::string::npos) continue;
                    const std::string a = tn->second + "::" + pair.substr(0, bar);
                    const std::string b = tn->second + "::" + pair.substr(bar + 1);

                    // Either field may be the stored one, so both
                    // orientations are priced. Taking only a-writes-b-reads
                    // silently drops the pair whenever the rule happened to
                    // list the reader first.
                    for (int flip = 0; flip < 2; ++flip) {
                        const auto &W =
                            setFor(facts.fieldWriters, flip ? b : a);
                        if (W.empty()) continue;
                        const std::string &other = flip ? a : b;
                        const auto &Rr = setFor(facts.fieldReaders, other);
                        const auto &R =
                            Rr.empty() ? setFor(facts.fieldWriters, other) : Rr;
                        if (R.empty()) continue;
                        const uint8_t wr = roles.rolesOf(W), rr = roles.rolesOf(R);
                        const bool disjoint = wr != ROLE_NONE &&
                                              rr != ROLE_NONE && (wr & rr) == 0;
                        CostEstimate est = estimateLineCost(
                            W, R, disjoint, rates, machine, calib,
                            workloadName, workload, flip ? b : a);
                        if (best.empty() ||
                            est.cyclesPerOp > best.cyclesPerOp) {
                            best = std::move(est);
                            bestW = &W;
                            bestR = &R;
                        }
                    }
                }
                if (!best.empty() && bestW && bestR) {
                    d.cost = std::move(best);
                    recordCostSites(d, *bestW, *bestR);
                }
            }
        }
        if (d.cost.empty())
            continue;
        // Without a workload budget a cost cannot be read as a share of an
        // operation, so it is reported and not graded. Grading it anyway
        // made every costed finding Informational on any target without a
        // config, which is a silent cap rather than an absent one.
        if (!workload.known()) {
            ++graded;
            d.escalations.push_back(
                "estimated cost " + milliToText(d.cost.cyclesPerOp) +
                " cycles per operation, ungraded: set workload_cycles_per_op "
                "to read it as a share of the target's own work");
            continue;
        }

        // An estimate above the whole per-operation budget is arithmetic,
        // not a finding: a hazard cannot cost more than the operation does,
        // so a term is wrong. Report the number, say it is implausible, and
        // do not let it carry a grade.
        if (d.cost.cyclesPerOp > toMilli(workload.cyclesPerOp)) {
            // Marked structurally as well as in prose, so a measurement
            // ingest can refuse to learn a residual from a number the model
            // has already disowned without parsing an escalation string.
            d.structuralEvidence["cost_implausible"] = "yes";
            d.escalations.push_back(
                "estimated cost " + milliToText(d.cost.cyclesPerOp) +
                " cycles per operation exceeds the whole " +
                std::to_string(workload.cyclesPerOp) +
                " cycle budget, so a term is wrong: reported, not graded");
            ++graded;
            continue;
        }
        const Severity supported =
            severityForCost(d.cost.cyclesPerOp, workload);
        d.mechanismClaims.push_back(
            {"the hazard costs enough of an operation to be worth acting on",
             "estimated cycles per operation above the dismissal threshold",
             claimFrom(d.cost.complete), supported, /*gating=*/true});
        std::string terms;
        for (const auto &t : d.cost.terms) {
            if (!terms.empty()) terms += " x ";
            terms += t.name + "=" + milliToText(t.value);
            if (!t.established) terms += "?";
        }
        d.escalations.push_back(
            "estimated cost " + milliToText(d.cost.cyclesPerOp) +
            " cycles per operation against a " +
            std::to_string(workload.cyclesPerOp) + " cycle budget on " +
            machine.name + " (" + terms + ")" +
            (d.cost.complete ? "" : "; terms marked ? are cost-maximising "
                                    "stand-ins, so this is an upper bound"));
        ++graded;
    }
    return graded;
}

// Give type-level findings the symbols that touch them. A layout finding
// reports at a struct declaration and names no function, so a per-symbol
// hardware profile has no key to look it up under.
//
// Capped, since all the set is asked is whether any of them ran and whether
// the event landed on any. Ordered so the cap cuts the same ones every
// time.
static unsigned attachAccessSymbols(std::vector<Diagnostic> &diagnostics,
                                    const ContentionGraph &graph) {
    constexpr size_t kMaxSymbols = 64;
    std::map<std::string, std::string> byOwner;
    for (const auto &[key, node] : graph.nodes) {
        auto &joined = byOwner[key.first];
        if (!joined.empty()) continue;
        std::set<std::string> all = node.writers();
        const auto readers = node.readers();
        all.insert(readers.begin(), readers.end());
        size_t n = 0;
        for (const auto &s : all) {
            if (n++ >= kMaxSymbols) break;
            if (!joined.empty()) joined += ',';
            joined += s;
        }
    }

    unsigned attached = 0;
    for (auto &d : diagnostics) {
        if (!d.functionName.empty()) continue;
        auto tn = d.structuralEvidence.find("type_name");
        if (tn == d.structuralEvidence.end()) continue;
        auto it = byOwner.find(tn->second);
        if (it == byOwner.end() || it->second.empty()) continue;
        d.structuralEvidence["access_symbols"] = it->second;
        ++attached;
    }
    return attached;
}

static constexpr const char *kTrueSharingMechanism = "coherence_true_sharing";

// Where FL006's candidates died, per gate.
//
// A rule that reports nothing looks exactly like a clean scan, and the canary
// only proves it can fire somewhere. On a real target you want to know which
// precondition failed, because "this program doesn't do that" and "we never
// established it" are the same silence and only one is our bug.
struct TrueSharingGates {
    unsigned residents = 0;
    unsigned noEscapeRoute = 0;
    unsigned notBothSides = 0;
    unsigned writesUnobservable = 0;
    unsigned handedNotStanding = 0;
    unsigned perRequestObject = 0;
    unsigned writeDoesNotRecur = 0;
    unsigned everyReaderAlsoWrites = 0;
    unsigned oneRoleOnly = 0;
    unsigned emitted = 0;

    std::string summary() const {
        return std::to_string(emitted) + " finding(s) from " +
               std::to_string(residents) + " field(s) on modelled lines; "
               "rejected " + std::to_string(noEscapeRoute) +
               " no thread route, " + std::to_string(notBothSides) +
               " not both written and read, " +
               std::to_string(writesUnobservable) +
               " writes not fully visible, " +
               std::to_string(handedNotStanding) + " handed not standing, " +
               std::to_string(perRequestObject) +
               " reached through a pointer to a per-request object, " +
               std::to_string(writeDoesNotRecur) + " write does not recur, " +
               std::to_string(everyReaderAlsoWrites) +
               " every reader also writes, " + std::to_string(oneRoleOnly) +
               " single thread role";
    }
};

// FL006: one field, stored by one role and read by another.
//
// FL002 covers two distinct fields colliding on a line, where padding fixes
// it because they never needed to be neighbours. Here the readers want the
// value, so padding only relocates the transfer. Different fix, different
// sentence, and no pair of field names to describe it with.
static unsigned emitTrueSharingFindings(
        std::vector<Diagnostic> &diagnostics,
        const ContentionGraph &graph,
        const EscapeSummary &escape,
        const ThreadRoleSummary &facts,
        const ThreadRoleVerdicts &roles,
        const std::map<std::string, HotnessSource> &globalHot,
        const RateModel &rates,
        const MachineModel &machine,
        const CostCalibration &calib,
        const std::string &workloadName,
        const WorkloadModel &workload,
        TrueSharingGates &gates) {
    unsigned emitted = 0;
    for (const auto &[key, node] : graph.nodes) {
        (void)key;
        const unsigned onLine = static_cast<unsigned>(node.residents.size());
        gates.residents += onLine;
        auto sit = escape.find(node.owner);
        if (sit == escape.end()) {
            gates.noEscapeRoute += onLine;
            continue;
        }
        // Nothing reaches this type from another thread, so a store on it
        // invalidates nobody. Same gate every sharing rule here uses, and
        // the reason it is concurrency evidence rather than atomicity: a
        // single-writer field is deliberately non-atomic and still traded.
        if (!sit->second.hasSharingRoute() && !sit->second.hasAnyEscape()) {
            gates.noEscapeRoute += onLine;
            continue;
        }

        // Whether the program mints one of these per unit of work.
        bool freshlyAllocatedPerOp = false;
        if (auto a = facts.allocatorsOfType.find(node.owner);
            a != facts.allocatorsOfType.end())
            for (const auto &fn : a->second)
                if (globalHot.count(fn)) { freshlyAllocatedPerOp = true; break; }

        for (const auto &r : node.residents) {
            if (!r.written() || !r.read()) {
                ++gates.notBothSides;
                continue;
            }
            // If we can't see all the writes, silence tells us nothing about
            // how often the line gets invalidated.
            if (!r.writesObservable()) {
                ++gates.writesUnobservable;
                continue;
            }

            // Writes through a handed-in pointer move with the object and
            // contend with nothing; without this we fire on every field of
            // every per-request struct. Sometimes only the reads can tell:
            // a setter writes through its parameter while the command path
            // reads the one global instance. Weaker, so it lands in the claim
            // rather than passing silently.
            const bool standingWrites = r.access.standing();
            const bool oneObject = standingWrites || r.access.standingReads();
            if (!standingWrites && !r.access.anyStandingRead()) {
                ++gates.handedNotStanding;
                continue;
            }

            // The store has to recur, or the line settles into Shared after
            // the first read and stops costing anything. Object freshness and
            // writer hotness are deliberately not gates here: an object
            // handed between threads is contended on exactly the fields they
            // hand it with. Both survive below as evidence.
            const bool loopWrite = r.loopWritten();
            bool writerHot = false;
            for (const auto &fn : r.writers)
                if (globalHot.count(fn)) { writerHot = true; break; }
            if (!loopWrite && !rates.recurrent(r.writers)) {
                ++gates.writeDoesNotRecur;
                continue;
            }

            std::set<std::string> pureReaders;
            for (const auto &fn : r.readers)
                if (!r.writers.count(fn))
                    pureReaders.insert(fn);
            if (pureReaders.empty()) {
                ++gates.everyReaderAlsoWrites;
                continue;
            }

            // Disjointness is a claim about the whole set, so it takes the
            // strict verdict. Reach is a lower bound, so it takes the
            // attributed subset: an unattributed reader can only add a role.
            const uint8_t wr = roles.rolesOf(r.writers);
            const uint8_t rr = roles.rolesOf(pureReaders);
            const bool disjoint =
                wr != ROLE_NONE && rr != ROLE_NONE && (wr & rr) == 0;

            const uint8_t knownW = roles.knownRolesOf(r.writers);
            const uint8_t knownR = roles.knownRolesOf(pureReaders);
            const bool spansRoles =
                ThreadRoleVerdicts::roleCount(knownR) >= 2 ||
                (knownW != ROLE_NONE && knownR != ROLE_NONE &&
                 (knownW & knownR) == 0);
            if (!disjoint && !spansRoles) {
                ++gates.oneRoleOnly;
                continue;
            }

            bool readerHot = false;
            for (const auto &fn : pureReaders)
                if (globalHot.count(fn)) { readerHot = true; break; }

            Diagnostic d;
            d.ruleID = "FL006";
            d.title = "Cross-Thread Read of a Recurrently Written Field";
            d.severity = Severity::High;
            d.confidence = 0.75;
            d.evidenceTier = EvidenceTier::Likely;
            d.location.file = node.declFile;
            // The field's own line, so two fields of one record are two
            // findings rather than one after dedup.
            d.location.line = r.declLine ? r.declLine : node.declLine;
            d.functionName = *r.writers.begin();
            d.hardwareReasoning =
                "'" + node.owner + "::" + r.field +
                "' is stored from " + std::to_string(r.writers.size()) +
                " function(s) and read, without being written, from " +
                std::to_string(pureReaders.size()) +
                " more on a different thread role. Each store takes the line "
                "in Modified state and invalidates every core holding it "
                "Shared, so the next read on each of those cores pays a "
                "cross-core transfer rather than an L1 hit. The cost is one "
                "transfer per reading core per store, and it does not depend "
                "on the fields being distinct: this is the same field on "
                "both sides.";
            d.structuralEvidence = {
                {"type_name", node.owner},
                {"field", r.field},
                {"line_index", std::to_string(node.lineIndex)},
                {"write_sites", std::to_string(r.access.writeSites)},
                {"loop_write_sites", std::to_string(r.access.loopWriteSites)},
                {"standing_writes",
                 std::to_string(r.access.standingWriteSites)},
                {"handed_writes", std::to_string(r.access.handedWriteSites)},
                {"read_sites", std::to_string(r.access.readSites)},
                {"standing_reads",
                 std::to_string(r.access.standingReadSites)},
                {"handed_reads", std::to_string(r.access.handedReadSites)},
                {"atomic_field", r.isAtomic ? "yes" : "no"},
                {"roles_disjoint", disjoint ? "yes" : "no"},
            };
            if (!r.writeSites.empty()) {
                std::string sites;
                for (const auto &loc : r.writeSites) {
                    if (!sites.empty()) sites += ',';
                    sites += loc;
                }
                d.structuralEvidence["cost_write_sites"] = sites;
            }
            d.mitigation =
                "Padding does not help here: the readers want the value, so "
                "moving it to its own line keeps every transfer and only "
                "stops it dragging neighbours along. Cut the store rate or "
                "the reader count instead. Publish '" + r.field +
                "' once per outer iteration into a per-thread copy and read "
                "the copy, or hand it to each reader with the work it "
                "already receives.";

            d.mechanismClaims = {
                {"a store invalidates every core holding the line",
                 "the field is written and separately read, on one line",
                 ClaimState::Established, Severity::Medium},
                {"the writer and the readers reach one object",
                 standingWrites
                     ? "the stores reach a fixed object the program names"
                     : freshlyAllocatedPerOp
                         ? "the loads reach it through a global name, but the "
                           "program allocates one of these per unit of work, "
                           "so that name denotes a different object each time"
                     : oneObject
                         ? "the loads mostly reach a fixed object the program "
                           "names, while the stores arrive through a "
                           "parameter that may or may not be it"
                         : "some loads reach a fixed object the program "
                           "names, but most of the accesses on both sides "
                           "arrive through a parameter",
                 claimFrom(standingWrites ||
                           (oneObject && !freshlyAllocatedPerOp)),
                 Severity::High},
                {"the reading cores are not the storing core",
                 disjoint ? "writer and reader thread roles are provably "
                            "disjoint"
                          : "readers span more than one thread role",
                 claimFrom(disjoint || spansRoles), Severity::High},
                {"the invalidation recurs rather than settling",
                 writerHot ? "a storing function confirmed hot on the merged "
                             "call graph"
                           : "stores issued from inside a loop",
                 claimFrom(writerHot), Severity::Critical},
                {"the readers run often enough to pay it",
                 "a reading function confirmed hot on the merged call graph",
                 claimFrom(readerHot), Severity::Critical},
            };

            d.cost = estimateLineCost(
                r.writers, pureReaders, disjoint, rates, machine, calib,
                workloadName, workload, node.owner + "::" + r.field,
                kTrueSharingMechanism);
            recordCostSites(d, r.writers, pureReaders);

            diagnostics.push_back(std::move(d));
            ++emitted;
            ++gates.emitted;
        }
    }
    return emitted;
}

// A store to one field invalidates the whole line, so a core reading a
// neighbouring field re-fetches and pays what a second writer would. FL002
// only sees that when the store and the read compile together, and routinely
// they do not. Layout is a program fact and the access sets merge, so the
// join lives here.
static unsigned emitCrossTUSharedLineFindings(
        std::vector<Diagnostic> &diagnostics,
        const EscapeSummary &escape,
        const ThreadRoleSummary &facts,
        const ThreadRoleVerdicts &roles,
        const std::map<std::string, HotnessSource> &globalHot,
        const RateModel &rates,
        const MachineModel &machine,
        const CostCalibration &calib,
        const std::string &workloadName,
        const WorkloadModel &workload,
        uint64_t lineBytes) {
    if (lineBytes == 0)
        return 0;


    // A type already reported takes the pair as added evidence: a second
    // finding lands on the same record location and dedup drops the cross-TU
    // half rather than merging it. Every instance, not the first, since this
    // runs before dedup and a header-declared type carries one per including
    // TU.
    std::map<std::string, std::vector<Diagnostic *>> reported;
    for (auto &d : diagnostics) {
        if (d.suppressed || (d.ruleID != "FL002" && d.ruleID != "FL041"))
            continue;
        auto it = d.structuralEvidence.find("type_name");
        if (it != d.structuralEvidence.end() && !it->second.empty())
            reported[it->second].push_back(&d);
    }

    auto anyHot = [&globalHot](const std::set<std::string> &fns) {
        for (const auto &f : fns)
            if (globalHot.count(f)) return true;
        return false;
    };
    auto namesFor = [](const std::map<std::string, std::set<std::string>> &m,
                       const std::string &key) -> const std::set<std::string> * {
        auto it = m.find(key);
        return it == m.end() || it->second.empty() ? nullptr : &it->second;
    };
    // Every accessor on the main thread means no two cores hold the line, so
    // no store of one field costs the reader of another anything. Unknown
    // roles decline to conclude that, which is the direction that keeps a
    // finding rather than inventing one.
    auto allMainThread = [&roles](const std::set<std::string> &a,
                                  const std::set<std::string> &b) {
        for (const auto *s : {&a, &b})
            for (const auto &fn : *s)
                if (roles.roleOf(fn) != ROLE_MAIN)
                    return false;
        return true;
    };

    std::vector<std::string> typeNames;
    typeNames.reserve(escape.size());
    for (const auto &[name, sig] : escape)
        if (sig.fieldExtents.size() >= 2 && sig.declLine != 0)
            typeNames.push_back(name);
    // EscapeSummary is a hash map, and dedup runs before the output sort.
    std::sort(typeNames.begin(), typeNames.end());

    constexpr size_t kMaxReportedPairs = 5;
    // Ranking needs more than it reports, and a wide record has thousands of
    // co-resident pairs. Bounded because this runs once per routed type.
    constexpr size_t kMaxCandidates = 256;
    unsigned emitted = 0;
    for (const auto &typeName : typeNames) {
        const auto &sig = escape.at(typeName);
        // Two cores must be able to reach one instance. The map phase cannot
        // answer this: the record lives in a header and its global lives in
        // one .c.
        if (!sig.hasSharingRoute())
            continue;

        struct Hit {
            std::string writer, other;
            unsigned others;      // distinct readers, or distinct co-writers
            bool bothWritten;
            // The neighbour is read somewhere and written nowhere in the
            // merged program. It can only ever lose the line, never take it,
            // so every store to the writer costs each reading core a
            // re-fetch and nothing comes back the other way.
            bool otherNeverWritten;
            // Some writer of the stored field is confirmed hot over the
            // merged graph. Co-location with a field written twice at startup
            // costs nothing however widely the neighbour is read, which is
            // the same trap as grading coherence structure without a rate.
            bool hotWriter;
            const std::set<std::string> *writerSet = nullptr;
            const std::set<std::string> *otherSet = nullptr;
        };
        std::vector<Hit> hits;
        bool disjointRoles = false;
        bool anyMultiWriter = false;
        // Which field stores and which one only reads is not decided by the
        // order the names sort in, so both directions of every co-resident
        // pair are asked.
        auto consider = [&](const std::string &w, const std::string &o,
                            bool otherIsScalar) {
            const auto *writers = namesFor(facts.fieldWriters, typeName + "::" + w);
            if (!writers)
                return;
            const auto *coWriters =
                namesFor(facts.fieldWriters, typeName + "::" + o);
            if (coWriters) {
                unsigned distinct = 0;
                for (const auto &c : *coWriters)
                    if (!writers->count(c))
                        ++distinct;
                if (distinct && !allMainThread(*writers, *coWriters)) {
                    uint8_t a = roles.rolesOf(*writers), b = roles.rolesOf(*coWriters);
                    if (a != ROLE_NONE && b != ROLE_NONE && (a & b) == 0)
                        disjointRoles = true;
                    anyMultiWriter = true;
                    hits.push_back({w, o, distinct, true, false,
                                    anyHot(*writers) || anyHot(*coWriters),
                                    writers, coWriters});
                    return;
                }
            }
            const auto *readers = namesFor(facts.fieldReaders, typeName + "::" + o);
            if (!readers)
                return;
            // A function that also writes the field it reads makes this the
            // write/write case, not a reader paying for someone else's store.
            unsigned distinct = 0;
            for (const auto &r : *readers)
                if (!writers->count(r) && !(coWriters && coWriters->count(r)))
                    ++distinct;
            if (!distinct || allMainThread(*writers, *readers))
                return;
            uint8_t a = roles.rolesOf(*writers), b = roles.rolesOf(*readers);
            if (a != ROLE_NONE && b != ROLE_NONE && (a & b) == 0)
                disjointRoles = true;
            hits.push_back({w, o, distinct, false,
                            coWriters == nullptr && otherIsScalar,
                            anyHot(*writers), writers, readers});
        };

        for (auto a = sig.fieldExtents.begin();
             a != sig.fieldExtents.end() && hits.size() < kMaxCandidates; ++a) {
            if (a->second.sizeBytes == 0)
                continue;
            for (auto b = std::next(a);
                 b != sig.fieldExtents.end() && hits.size() < kMaxCandidates;
                 ++b) {
                if (b->second.sizeBytes == 0)
                    continue;
                if (!extentsCanCoReside(a->second.offsetBytes,
                                        a->second.sizeBytes,
                                        b->second.offsetBytes,
                                        b->second.sizeBytes,
                                        sig.recordAlignBytes, lineBytes))
                    continue;
                const size_t before = hits.size();
                consider(a->first, b->first, b->second.plainScalar);
                if (hits.size() == before)
                    consider(b->first, a->first, a->second.plainScalar);
            }
        }
        if (hits.empty())
            continue;
        // Field order is alphabetical, so on a wide record the first pairs
        // found say nothing. Rank by mechanism, then by how many functions
        // carry it; the name tail only keeps the order total.
        std::sort(hits.begin(), hits.end(), [](const Hit &x, const Hit &y) {
            // A never-written neighbour outranks a second writer. Two writers
            // trade the line and each pays once per alternation; one writer
            // against N reading cores costs N re-fetches per store, and the
            // fix is unambiguous because moving a field nothing writes can
            // break nothing.
            const bool xtop = x.otherNeverWritten && x.hotWriter;
            const bool ytop = y.otherNeverWritten && y.hotWriter;
            if (xtop != ytop) return xtop;
            if (x.otherNeverWritten != y.otherNeverWritten)
                return x.otherNeverWritten;
            if (x.bothWritten != y.bothWritten) return x.bothWritten;
            if (x.others != y.others) return x.others > y.others;
            if (x.writer != y.writer) return x.writer < y.writer;
            return x.other < y.other;
        });
        if (hits.size() > kMaxReportedPairs)
            hits.resize(kMaxReportedPairs);

        std::string detail;
        for (size_t i = 0; i < hits.size(); ++i) {
            if (i) detail += "; ";
            if (hits[i].bothWritten)
                detail += "'" + hits[i].writer + "' and '" + hits[i].other +
                          "' on one line are written from " +
                          std::to_string(hits[i].others) +
                          " function(s) that do not overlap";
            else if (hits[i].otherNeverWritten)
                detail += "'" + hits[i].writer + "' is stored while '" +
                          hits[i].other + "' on the same line is read from " +
                          std::to_string(hits[i].others) +
                          " function(s), with no write to it anywhere in the "
                          "scan" +
                          (hits[i].hotWriter
                               ? std::string(", and the store is on a "
                                             "confirmed-hot path")
                               : std::string(", though the store's own "
                                             "frequency is not established"));
            else
                detail += "'" + hits[i].writer + "' is stored while '" +
                          hits[i].other + "' on the same line is read from " +
                          std::to_string(hits[i].others) +
                          " function(s) that never write it";
        }

        auto existing = reported.find(typeName);
        if (existing != reported.end()) {
            CostEstimate est;
            if (hits[0].writerSet && hits[0].otherSet)
                est = estimateLineCost(*hits[0].writerSet, *hits[0].otherSet,
                                       disjointRoles, rates, machine, calib,
                                       workloadName, workload);
            for (auto *d : existing->second) {
                d->escalations.push_back(
                    "cross-TU line-sharing evidence: " + detail);
                if (d->cost.empty() && !est.empty()) {
                    d->cost = est;
                    recordCostSites(*d, *hits[0].writerSet, *hits[0].otherSet);
                }
            }
            continue;
        }

        Diagnostic d;
        d.ruleID = "FL002";
        d.title = "False Sharing Candidate";
        d.location.file = sig.declFile;
        d.location.line = sig.declLine;
        d.location.column = 1;
        // A reader pays one miss per remote store; two writers trade the line
        // in both directions. Real, and not the same cost.
        d.severity = anyMultiWriter ? Severity::High : Severity::Medium;
        d.confidence = disjointRoles ? 0.68 : 0.58;
        d.evidenceTier = EvidenceTier::Likely;

        std::ostringstream hw;
        hw << "Struct '" << typeName << "': ";
        if (hits[0].bothWritten)
            hw << "'" << hits[0].writer << "' and '" << hits[0].other
               << "' share a cache line and are written from disjoint sets of "
               << "functions, so each write pulls the line back in Modified "
               << "from the other core. ";
        else if (hits[0].otherNeverWritten)
            hw << "'" << hits[0].other << "' is read across the program and "
               << "written nowhere in it, and it shares a cache line with '"
               << hits[0].writer << "', which is stored. Every store takes "
               << "the line Exclusive and invalidates it in each core holding "
               << "the read-only field, so the cost scales with the number of "
               << "reading cores and nothing travels back the other way. ";
        else
            hw << "a store to '" << hits[0].writer << "' invalidates the cache "
               << "line holding '" << hits[0].other << "', which is read by "
               << "function(s) that never write it, so each store costs those "
               << "readers a re-fetch of a line they did not modify. ";
        hw << "The accesses are in different translation units, so no "
           << "single-TU view shows both.";
        d.hardwareReasoning = hw.str();

        std::string pairFields;
        for (size_t i = 0; i < hits.size(); ++i) {
            if (i) pairFields += ';';
            pairFields += hits[i].writer + "|" + hits[i].other;
        }
        d.structuralEvidence = {
            {"type_name", typeName},
            {"thread_escape", "true"},
            {"pair_fields", pairFields},
            {"cross_tu_line_sharing", "true"},
            {"atomics", sig.hasAtomics ? "yes" : "no"},
        };
        if (hits[0].writerSet && hits[0].otherSet) {
            d.cost = estimateLineCost(*hits[0].writerSet, *hits[0].otherSet,
                                      disjointRoles, rates, machine, calib,
                                      workloadName, workload);
            recordCostSites(d, *hits[0].writerSet, *hits[0].otherSet);
        }
        d.escalations.push_back("cross-TU line-sharing evidence: " + detail);
        if (disjointRoles)
            d.escalations.push_back(
                "the two access sets are on provably disjoint thread roles, "
                "so they run on different cores rather than possibly the same "
                "one");
        if (sig.hasDeliberateLayout)
            d.escalations.push_back(
                "deliberate cache-line layout detected on this type: verify "
                "the flagged field is not already isolated by design");

        d.mechanismClaims = {
            {"co-located mutable fields share a line",
             "two mutable fields co-resident under some base alignment", ClaimState::Established,
             Severity::Medium},
            {anyMultiWriter
                 ? "MESI invalidation ping-pong between the two writers"
                 : hits[0].otherNeverWritten
                       ? "each store invalidates a read-only field in every "
                         "core holding it"
                       : "a store to one downgrades the line under the other's reader",
             anyMultiWriter
                 ? "disjoint writer sets reaching both fields"
                 : hits[0].otherNeverWritten
                       ? "the neighbour has readers and no writer anywhere in "
                         "the merged program"
                       : "a writer of one field and a non-writing reader of the other",
             ClaimState::Established, d.severity},
            // The gate the map phase cannot answer: the record lives in a
            // header and its global lives in one .c.
            {"two threads reach the same instance",
             "some TU shows a shared instance and a thread-borne writer",
             ClaimState::Established,
             d.severity, /*gating=*/true},
        };
        d.mitigation =
            hits[0].otherNeverWritten
                ? "Move '" + hits[0].other + "' off this line. Nothing in the "
                  "program writes it, so relocating it into a read-only block "
                  "beside the other never-written fields cannot change "
                  "behaviour, and it removes the invalidation for every "
                  "reading core at once. Aligning the record does not help "
                  "when both fields sit inside one element."
                : "Move the stored field off the line the readers touch, with "
                  "alignas(64) or by grouping read-mostly fields together. "
                  "Padding the readers apart from each other does nothing "
                  "here: the cost is one store landing on a line that other "
                  "cores hold.";

        diagnostics.push_back(std::move(d));
        ++emitted;
    }
    return emitted;
}

// Findings from the compiler's own remark stream. Hot-filtered because one
// mid-sized C file emits ~12.8k records.
static unsigned emitOptRemarkFindings(
        std::vector<Diagnostic> &out,
        const std::vector<OptRemark> &remarks,
        const std::map<std::string, HotnessSource> &globalHot,
        const std::vector<std::string> &hotPatterns) {
    // Keyed on the site too: overloads share a qualified name on both sides
    // of the join, so merging them drops one. Capped per function because a
    // single function can carry 25 of these.
    constexpr unsigned kMaxSitesPerFunction = 3;
    std::set<std::tuple<std::string, std::string, std::string, unsigned>> seen;
    std::map<std::pair<std::string, std::string>, unsigned> total, shown;
    for (const auto &r : remarks)
        ++total[{r.function, r.name}];
    unsigned emitted = 0;

    for (const auto &r : remarks) {
        // Config patterns cover hot paths the call graph cannot reach,
        // which is what function-pointer dispatch produces.
        auto hot = globalHot.find(r.function);
        HotnessSource src = HotnessSource::None;
        if (hot != globalHot.end()) {
            src = hot->second;
        } else {
            for (const auto &p : hotPatterns)
                if (fnmatch(p.c_str(), r.function.c_str(), 0) == 0) {
                    src = HotnessSource::Declared;
                    break;
                }
            if (src == HotnessSource::None)
                continue;
        }
        if (!seen.emplace(r.function, r.name, r.file, r.line).second)
            continue;
        unsigned &n = shown[{r.function, r.name}];
        if (n >= kMaxSitesPerFunction)
            continue;
        ++n;

        Diagnostic d;
        d.ruleID = "C002";
        d.title = "Loop-Invariant Load Not Hoisted";
        d.severity = Severity::Medium;
        d.confidence = 0.80;
        d.evidenceTier = EvidenceTier::Likely;
        d.functionName = r.function;
        d.location.file = r.file;
        d.location.line = r.line;
        d.location.column = r.column;
        d.hotness = static_cast<uint8_t>(src);

        d.hardwareReasoning =
            "The address of this load does not change across the loop, but "
            "LICM could not hoist it: some store in the body may alias it, so "
            "the load repeats every iteration. The compiler is reporting that "
            "its alias analysis lost here, which is weaker than a claim that "
            "the pointers do alias.";

        d.structuralEvidence = {
            {"pass", r.pass},
            {"remark", r.name},
            {"function", r.function},
            {"hotness", hotnessSourceName(src)},
        };
        if (r.count)
            d.structuralEvidence["copies"] = std::to_string(r.count);
        if (!r.detail.empty())
            d.structuralEvidence["compiler_note"] = r.detail;
        const unsigned sites = total[{r.function, r.name}];
        d.structuralEvidence["sites_in_function"] = std::to_string(sites);
        if (sites > kMaxSitesPerFunction)
            d.escalations.push_back(
                std::to_string(sites) + " loops in this function carry the "
                "same remark; " + std::to_string(kMaxSitesPerFunction) +
                " are reported. Re-run after a fix rather than working the "
                "list, since one aliasing change can clear several");

        d.mitigation =
            "Hoist the load into a local before the loop where the invariance "
            "holds, or qualify the pointers with restrict if they genuinely "
            "do not alias. Do not add restrict to silence this without "
            "establishing that: it is a promise to the compiler, not a hint.";

        d.mechanismClaims = {
            {"a load repeated per iteration at a loop-invariant address",
             "the compiler recorded the decision in its own remark stream",
             ClaimState::Established, Severity::Medium},
            {std::string("this code runs often enough for the cost to recur (") +
                 hotnessSourceName(src) + ", cross-TU)",
             "hotness established by profile or declaration, not inferred "
             "from shape alone",
             claimFrom(src >= HotnessSource::Declared),
             hotnessSupportedSeverity(src, Severity::Medium),
             /*gating=*/true},
        };
        out.push_back(std::move(d));
        ++emitted;
    }
    return emitted;
}

// FL092: unapplied in-tree mitigation. Synthesized when an attributed FL002
// sits in a codebase that already line-isolates other types, so the codebase
// itself validates both the hazard class and the fix idiom and this struct
// simply never received it. Post-dedup, one compound per surviving component,
// never outranking the component's mitigation-adjusted severity.
static unsigned synthesizeUnappliedMitigation(
        std::vector<Diagnostic> &diagnostics,
        const EscapeSummary &globalEscape) {
    std::vector<std::string> mitigated;
    for (const auto &[name, sig] : globalEscape)
        if (sig.hasDeliberateLayout)
            mitigated.push_back(name);
    if (mitigated.empty())
        return 0;
    std::sort(mitigated.begin(), mitigated.end());

    std::vector<Diagnostic> compounds;
    std::set<std::string> emittedTypes;
    for (const auto &d : diagnostics) {
        // FL002 joins at pair granularity; FL090 at struct granularity,
        // large structs put the disjoint pair beyond FL002's pair-evidence
        // cap, and FL090's uncapped type-level attribution catches those.
        // One compound per type: FL002 wins the tie by sort order.
        if (d.suppressed || (d.ruleID != "FL002" && d.ruleID != "FL090"))
            continue;
        auto tit = d.structuralEvidence.find("type_name");
        if (tit == d.structuralEvidence.end() || tit->second.empty())
            continue;
        if (emittedTypes.count(tit->second))
            continue;
        auto git = globalEscape.find(tit->second);
        if (git != globalEscape.end() && git->second.hasDeliberateLayout)
            continue; // already carries the idiom; FL002's demotion applies
        bool attributed = false;
        for (const auto &e : d.escalations)
            if (e.rfind("cross-TU thread-role attribution", 0) == 0) {
                attributed = true;
                break;
            }
        if (!attributed)
            continue;

        Diagnostic c;
        c.ruleID = "FL092";
        c.title = "Unapplied In-Tree Mitigation";
        c.severity = d.severity;
        c.confidence = d.confidence;
        c.evidenceTier = d.evidenceTier;
        c.location = d.location;
        c.functionName = d.functionName;
        c.hardwareReasoning =
            "Struct '" + tit->second + "' has false sharing with "
            "cross-thread-attributed writers while this codebase already "
            "isolates " + std::to_string(mitigated.size()) +
            " other type(s) on dedicated cache lines (e.g. '" +
            mitigated.front() + "'). The MESI invalidation mechanism and "
            "its fix idiom are both established in-tree; this struct never "
            "received the treatment.";
        c.structuralEvidence = {
            {"component", d.ruleID},
            {"type_name", tit->second},
            {"mitigated_exemplar", mitigated.front()},
            {"mitigated_type_count", std::to_string(mitigated.size())},
        };
        c.mitigation =
            "Apply the codebase's existing isolation idiom (as on '" +
            mitigated.front() + "') to the disjoint-writer fields of '" +
            tit->second + "'.";
        // FL092 asserts nothing about hardware on its own: it inherits the
        // component's mechanism and adds that this codebase already knows
        // the fix. So it can never outrank the finding it was built from.
        c.mechanismClaims = {
            {"the component hazard's own mechanism",
             "the attributed finding established it", ClaimState::Established,
             d.severitySupportedByClaims()},
            {"the fix idiom is established in-tree and was not applied here",
             "another type in this codebase is deliberately line-isolated",
             claimFrom(!mitigated.empty()), d.severity},
        };
        c.escalations = {
            "precedent join: " + std::to_string(mitigated.size()) +
            " deliberately line-isolated type(s) in this codebase"};
        emittedTypes.insert(tit->second);
        compounds.push_back(std::move(c));
    }

    for (auto &c : compounds)
        diagnostics.push_back(std::move(c));
    return static_cast<unsigned>(compounds.size());
}

// Two cores can only fight over a cache line if they reach the same object.
// A rule cannot decide that: hasGlobalInstance is a per-TU fact, the record
// lives in a header and its global lives in one .c, so at rule time the
// answer is false almost everywhere it matters.
// Objects that two thread roles both reach, with at least one writer.
//
// The type-keyed model could not ask this. Two globals of one type were one
// node there, so two roles touching different instances read the same as two
// roles touching one. Object identity makes it a fact about storage.
static std::set<std::string> reachedByTwoRoles(const MemoryModel &model,
                                               const ThreadRoleVerdicts &roles) {
    std::set<std::string> out;
    for (const auto &[id, acc] : model.objects) {
        if (!obj::isStatic(id) && !obj::isHeap(id))
            continue;
        std::set<std::string> touchers = acc.writers();
        if (touchers.empty())
            continue;  // a line only read by anyone costs no coherence traffic
        const auto rs = acc.readers();
        touchers.insert(rs.begin(), rs.end());
        if (ThreadRoleVerdicts::roleCount(roles.knownRolesOf(touchers)) >= 2)
            out.insert(id);
    }
    return out;
}

// Settle the sharing claim on the object rather than on the type. Additive:
// it establishes what no per-type disjunction could see, and never withdraws.
static unsigned applyObjectSharingVerdict(std::vector<Diagnostic> &diagnostics,
                                          const MemoryModel &model,
                                          const ThreadRoleVerdicts &roles) {
    const std::set<std::string> shared = reachedByTwoRoles(model, roles);
    if (shared.empty())
        return 0;

    unsigned settled = 0;
    for (auto &d : diagnostics) {
        if (d.suppressed) continue;
        if (d.ruleID != "FL002" && d.ruleID != "FL041") continue;
        auto it = d.structuralEvidence.find("global_instances");
        if (it == d.structuralEvidence.end() || it->second.empty()) continue;

        std::string named;
        const std::string &gs = it->second;
        for (size_t start = 0; start < gs.size();) {
            size_t end = gs.find(';', start);
            std::string g = gs.substr(start, end == std::string::npos
                                                 ? std::string::npos
                                                 : end - start);
            if (!g.empty() && shared.count(obj::global(g))) {
                if (!named.empty()) named += ", ";
                named += g;
            }
            if (end == std::string::npos) break;
            start = end + 1;
        }
        if (named.empty()) continue;

        d.settleClaim("MESI invalidation ping-pong", ClaimState::Established,
                      "two thread roles reach '" + named + "' itself, not "
                      "merely two instances of its type");
        // The type-level pass may have refuted the route gate from a
        // disjunction over every instance of the type. Naming the object is
        // the finer instrument and overrides it, the same precedence a
        // profile takes over a declaration.
        d.settleClaim("two threads reach the same instance",
                      ClaimState::Established,
                      "object '" + named + "' is reached by two roles");
        d.escalations.push_back(
            "object-level sharing: '" + named +
            "' is reached by more than one thread role");
        ++settled;
    }
    return settled;
}

struct SharingRouteVerdict {
    unsigned refuted = 0;  // no route, and absence of one is observable
    unsigned capped  = 0;  // no route found, but the tracker could not have seen one
    bool vocabularyDark = false;  // no thread route anywhere: see below
};

static SharingRouteVerdict
applySharingRouteVerdict(std::vector<Diagnostic> &diagnostics,
                         const EscapeSummary &summary) {
    SharingRouteVerdict out;

    // A codebase spawning through its own wrapper presents exactly as one
    // that never spawns, so refuting on the absence would be mass recall
    // loss. Require the instrument to fire somewhere first, as
    // bench/accept.sh requires of perf c2c.
    bool anyThreadRoute = false;
    for (const auto &[name, sig] : summary)
        if (sig.hasThreadRoute()) { anyThreadRoute = true; break; }
    out.vocabularyDark = !anyThreadRoute;

    for (auto &d : diagnostics) {
        if (d.suppressed) continue;
        // Rules whose whole claim is cross-core contention on one object.
        if (d.ruleID != "FL002" && d.ruleID != "FL041") continue;
        auto it = d.structuralEvidence.find("type_name");
        if (it == d.structuralEvidence.end() || it->second.empty()) continue;
        // ';'-separated: a compound may name several types. Any one of them
        // being shared leaves the finding alone.
        bool anyShared = false, anyKnown = false, allRefuted = true;
        const std::string &ts = it->second;
        for (size_t start = 0; start < ts.size();) {
            size_t end = ts.find(';', start);
            std::string t = ts.substr(start, end == std::string::npos
                                                 ? std::string::npos
                                                 : end - start);
            if (!t.empty()) {
                auto sit = summary.find(t);
                if (sit != summary.end()) {
                    anyKnown = true;
                    if (sit->second.hasSharingRoute()) anyShared = true;
                    if (!sit->second.sharingRouteRefuted()) allRefuted = false;
                }
            }
            if (end == std::string::npos) break;
            start = end + 1;
        }
        // Absent from the summary means unanalyzed, not disproven.
        if (!anyKnown || anyShared) continue;

        // A line no second core ever holds stays in M state: no RFO from a
        // peer, no HITM. The mechanism is ruled out, not unwitnessed.
        const bool observable = allRefuted && !out.vocabularyDark;
        d.mechanismClaims.push_back(
            {"two threads reach the same instance",
             "some TU shows a shared instance and a thread-borne writer",
             observable ? ClaimState::Refuted : ClaimState::Unknown,
             Severity::Medium, /*gating=*/true,
             observable ? "no TU reported a shared instance with a "
                          "thread-borne writer, across writes this analysis "
                          "can see"
                        : std::string{}});
        if (observable) {
            ++out.refuted;
        } else {
            d.escalations.push_back(
                "no TU showed a thread reaching a shared instance of this "
                "type: co-location is real, cross-core contention is not "
                "established");
            ++out.capped;
        }
    }
    return out;
}

// Drop thread_escape findings on types that no TU ever showed escaping.
static unsigned applyCrossTUEscapeSuppression(
        std::vector<Diagnostic> &diagnostics,
        const EscapeSummary &globalEscape,
        unsigned totalTUs) {
    if (totalTUs <= 1)
        return 0;

    unsigned suppressed = 0;
    for (auto &d : diagnostics) {
        if (d.suppressed) continue;

        auto eit = d.structuralEvidence.find("thread_escape");
        if (eit == d.structuralEvidence.end()) continue;
        if (eit->second != "true" && eit->second != "yes") continue;

        // Proven-tier findings are never suppressed.
        if (d.evidenceTier == EvidenceTier::Proven)
            continue;

        auto tit = d.structuralEvidence.find("type_name");
        if (tit == d.structuralEvidence.end())
            continue;

        auto git = globalEscape.find(tit->second);
        if (git != globalEscape.end() && git->second.hasAnyEscape())
            continue; // Global evidence confirms escape.

        d.suppressed = true;
        d.escalations.push_back(
            "cross-TU suppression: no escape evidence across " +
            std::to_string(totalTUs) + " TUs");
        ++suppressed;
    }
    return suppressed;
}

// severity desc, then file/line/column/ruleID: the output-order contract.
static bool outputOrder(const Diagnostic &a, const Diagnostic &b) {
    if (a.severity != b.severity)
        return static_cast<uint8_t>(a.severity) >
               static_cast<uint8_t>(b.severity);
    if (a.location.file != b.location.file)
        return a.location.file < b.location.file;
    if (a.location.line != b.location.line)
        return a.location.line < b.location.line;
    if (a.location.column != b.location.column)
        return a.location.column < b.location.column;
    if (a.ruleID != b.ruleID)
        return a.ruleID < b.ruleID;
    return diagnosticContentLess(a, b);
}

static void filterAndSort(const FilterOptions &filter,
                           std::vector<Diagnostic> &diagnostics) {
    diagnostics.erase(
        std::remove_if(diagnostics.begin(), diagnostics.end(),
                       [&](const Diagnostic &d) {
                           if (d.suppressed)
                               return true;
                           if (static_cast<uint8_t>(d.severity) <
                               static_cast<uint8_t>(filter.minSeverity))
                               return true;
                           if (static_cast<uint8_t>(d.evidenceTier) >
                               static_cast<uint8_t>(filter.minEvidenceTier))
                               return true;
                           return false;
                       }),
        diagnostics.end());

    std::sort(diagnostics.begin(), diagnostics.end(), outputOrder);
}

// --- Entry points ---

const std::vector<std::string> &reducePhaseHazardRules() {
    static const std::vector<std::string> kIDs = {"FL003", "FL004",
                                                 "FL091", "FL092"};
    return kIDs;
}

ScanResult ScanPipeline::execute(const ScanRequest &request) {
    std::string dbPath = request.compileDBPath;

    // Autodiscover compile_commands.json if not explicitly provided.
    if (dbPath.empty() && !request.workingDirectory.empty()) {
        report("compile_db", "Searching for compile_commands.json");
        if (request.trustBuildSystem)
            dbPath = CompileDBResolver::discoverOrGenerate(request.workingDirectory);
        else
            dbPath = CompileDBResolver::discover(request.workingDirectory);
        if (dbPath.empty()) {
            llvm::errs() << "lshaz: error: no compile_commands.json found in "
                         << request.workingDirectory;
            if (!request.trustBuildSystem)
                llvm::errs() << "\n  Build system execution disabled for "
                                "untrusted source. Use --trust-build-system "
                                "to allow cmake/meson/bear.";
            else
                llvm::errs() << " (also tried cmake generation)";
            llvm::errs() << "\n  searched: ";
            for (const auto &p : CompileDBResolver::candidatePaths(
                     request.workingDirectory))
                llvm::errs() << "\n    " << p;
            llvm::errs() << "\n";
            ScanResult result;
            result.status = ScanStatus::ToolError;
            return result;
        }
        report("compile_db", "Found " + dbPath);
    }

    if (dbPath.empty()) {
        llvm::errs() << "lshaz: error: no compile database path specified "
                     << "and no working directory for autodiscovery\n";
        ScanResult result;
        result.status = ScanStatus::ToolError;
        return result;
    }

    report("compile_db", "Loading " + dbPath);
    std::string dbError;
    auto jsonDB = clang::tooling::JSONCompilationDatabase::loadFromFile(
        dbPath, dbError,
        clang::tooling::JSONCommandLineSyntax::AutoDetect);
    if (!jsonDB) {
        llvm::errs() << "lshaz: error: " << dbError << "\n";
        ScanResult result;
        result.status = ScanStatus::ToolError;
        return result;
    }

    // Wrap in AbsolutePathCompilationDatabase to resolve all relative
    // paths at load time. This eliminates ClangTool's process-global
    // chdir() calls, which race between threads in parallel scans.
    AbsolutePathCompilationDatabase compDB(std::move(jsonDB));

    std::vector<std::string> sources = request.sourceFiles;
    if (sources.empty()) {
        sources = compDB.getAllFiles();
        std::sort(sources.begin(), sources.end());
    }

    unsigned vendored = 0;
    sources = filterSources(sources, request.filter, vendored);
    auto r = run(request, compDB, sources);
    r.vendoredTUsSkipped = vendored;
    return r;
}

ScanResult ScanPipeline::executeWithDB(
        const ScanRequest &request,
        const clang::tooling::CompilationDatabase &compDB,
        const std::vector<std::string> &sources) {
    unsigned vendored = 0;
    auto filtered = filterSources(sources, request.filter, vendored);
    auto r = run(request, compDB, filtered);
    r.vendoredTUsSkipped = vendored;
    return r;
}

// Compute the Clang resource directory for the LLVM this binary was linked
// against.  ClangTool normally derives it from the compiler path listed in
// compile_commands.json, which breaks when the project was built with gcc.
static std::string detectResourceDir() {
#ifdef LLVM_LIBRARY_DIR
    // LLVM_LIBRARY_DIR is injected via CMake (e.g. /opt/llvm/lib).
    // CLANG_VERSION_MAJOR comes from <clang/Basic/Version.inc>.
    // The resource dir lives at <lib-dir>/clang/<major-version>.
    std::string candidate = std::string(LLVM_LIBRARY_DIR) +
        "/clang/" + std::to_string(CLANG_VERSION_MAJOR);
    if (llvm::sys::fs::is_directory(candidate))
        return candidate;
#endif
    return {};
}

// Returns true if the compiler path looks like clang/clang++.
static bool compilerIsClang(const std::string &compiler) {
    llvm::StringRef stem = llvm::sys::path::stem(compiler);
    return stem.starts_with("clang");
}

// Only inject -resource-dir when the compile_commands.json compiler is not
// clang/clang++ (which already knows its own resource dir).
static void addResourceDirAdjuster(
        clang::tooling::ClangTool &tool,
        const clang::tooling::CompilationDatabase &compDB,
        const std::string &sourceFile) {
    static const std::string resDir = detectResourceDir();
    if (resDir.empty())
        return;
    auto cmds = compDB.getCompileCommands(sourceFile);
    if (!cmds.empty() && compilerIsClang(cmds.front().CommandLine.front()))
        return;
    static const std::string arg = "-resource-dir=" + resDir;
    tool.appendArgumentsAdjuster(
        clang::tooling::getInsertArgumentAdjuster(
            arg.c_str(),
            clang::tooling::ArgumentInsertPosition::BEGIN));
}

// --- Shared pipeline implementation ---

ScanResult ScanPipeline::run(
        const ScanRequest &request,
        const clang::tooling::CompilationDatabase &compDB,
        const std::vector<std::string> &sources) {
    ScanResult result;
    std::vector<OptRemark> optRemarks;
    unsigned remarkFilesFailed = 0;
    std::vector<FailedTU> failedTUsDetailed; // For header fingerprint detection

    result.metadata.toolVersion = kToolVersion;
    result.metadata.irOptLevel = request.ir.optLevel;
    result.metadata.irEnabled = request.ir.enabled;
    result.metadata.timestampEpochSec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    result.metadata.sourceFiles = sources;
    result.totalTUsAnalyzed = static_cast<unsigned>(sources.size());

    report("analysis", std::to_string(sources.size()) + " translation unit(s)");

    auto profileHotFuncs = loadProfileHotFunctions(request);

    // AST analysis. Parallel when multiple TUs and jobs > 1.
    unsigned jobs = request.analysisJobs;
    if (jobs == 0)
        jobs = std::max(1u, std::thread::hardware_concurrency());
    if (jobs > static_cast<unsigned>(sources.size()))
        jobs = static_cast<unsigned>(sources.size());

    const unsigned shardMemoryLimitMB =
        resolveShardMemoryLimitMB(request.memoryLimitMB, jobs);
    if (shardMemoryLimitMB == 0) {
        llvm::errs() << "lshaz: WARNING cannot read available memory, shards "
                        "run uncapped; a heavy TU can OOM the host\n";
    } else if (jobs > 1) {
        report("memory", std::to_string(shardMemoryLimitMB) +
                         " MiB cap per shard");
    }

    llvm::CrashRecoveryContext::Enable();

    // Pass one. Parses each TU and records structure only, so the parent can
    // close the project's allocator vocabulary before any rule runs. A
    // wrapper's body and its callers are in different TUs, so no per-TU pass
    // can resolve one.
    Config analysisConfig = request.config;
    {
        ThreadRoleSummary vocabFacts;
        unsigned parsed = 0;
        // A TU that crashes the prepass is skipped, not fatal: the vocabulary
        // is then smaller and the conjuncts fail closed.
        // The prepass reads no config beyond the compile command, so its
        // entries stay valid across rule and threshold edits that invalidate
        // pass two.
        TUCache vocabCache(request.config.cacheDir.empty()
                               ? std::string()
                               : request.config.cacheDir + "/vocab");
        auto cacheKey = [&](const std::string &src) {
            auto cmds = compDB.getCompileCommands(src);
            return TUCache::keyFor(src,
                                   cmds.empty()
                                       ? std::vector<std::string>()
                                       : cmds.front().CommandLine,
                                   "vocab");
        };
        auto prescanOne = [&](const std::string &src,
                              ThreadRoleSummary &into) -> bool {
            const std::string key = vocabCache.enabled() ? cacheKey(src)
                                                         : std::string();
            VocabularyActionFactory vf;
            llvm::CrashRecoveryContext CRC;
            int rc = 1;
            bool ok = CRC.RunSafely([&]() {
                std::vector<std::string> one = {src};
                clang::tooling::ClangTool tool(compDB, one);
                tool.setPrintErrorMessage(false);
                addResourceDirAdjuster(tool, compDB, src);
                rc = tool.run(&vf);
            });
            const bool clean = ok && rc == 0;
            // Only a clean parse is cached. Storing a crash would replay it
            // forever without ever retrying the TU.
            if (vocabCache.enabled() && clean && !vf.deps().empty())
                vocabCache.store(key, vf.deps(),
                                 serializeShardResult(0, {}, {}, {}, vf.facts(),
                                                      {}, {}, {}, src));
            into.merge(vf.facts());
            return clean;
        };

        // Served in the parent, before any fork: a child cannot report its
        // hit count back without extending the protocol, and a hit costs only
        // a file read.
        std::vector<std::string> toParse;
        for (const auto &src : sources) {
            std::string rec;
            ShardIPC r;
            if (vocabCache.enabled() &&
                vocabCache.lookup(cacheKey(src), rec) &&
                deserializeShardResult(rec, r)) {
                vocabFacts.merge(r.threadRoles);
                ++parsed;
                continue;
            }
            toParse.push_back(src);
        }

        if (jobs <= 1 || toParse.size() <= 1) {
            for (const auto &src : toParse)
                if (prescanOne(src, vocabFacts))
                    ++parsed;
        } else {
            // Same sharding and fork isolation the analysis pass uses, for
            // the same reason: ClangTool's global state is not thread-safe.
            // Sequential, this prepass dominates a large scan.
            std::vector<std::vector<std::string>> vshards(jobs);
            for (size_t i = 0; i < toParse.size(); ++i)
                vshards[i % jobs].push_back(toParse[i]);

            std::vector<std::pair<pid_t, std::string>> kids;
            for (unsigned j = 0; j < jobs; ++j) {
                if (vshards[j].empty()) continue;
                // O_EXCL with a random component, and the child inherits the
                // descriptor rather than reopening by name: a predictable path
                // opened for truncation is a symlink clobber on a shared host.
                int ipcFD = -1;
                llvm::SmallString<128> p;
                if (llvm::sys::fs::createTemporaryFile("lshaz-vocab", "json",
                                                       ipcFD, p)) {
                    for (const auto &src : vshards[j])
                        if (prescanOne(src, vocabFacts))
                            ++parsed;
                    continue;
                }

                pid_t pid = fork();
                if (pid < 0) {
                    // Fall back rather than lose the shard: a smaller
                    // vocabulary silently weakens every rule downstream.
                    for (const auto &src : vshards[j])
                        if (prescanOne(src, vocabFacts))
                            ++parsed;
                    continue;
                }
                if (pid == 0) {
                    llvm::CrashRecoveryContext::Enable();
                    llvm::raw_fd_ostream o(ipcFD, /*shouldClose=*/true);
                    for (const auto &src : vshards[j]) {
                        ThreadRoleSummary one;
                        int rc = prescanOne(src, one) ? 0 : 1;
                        o << serializeShardResult(rc, {}, {}, {}, one, {}, {}, {},
                                                  src) << "\n";
                        o.flush();
                    }
                    o.close();
                    _exit(0);
                }
                ::close(ipcFD);   // the child owns it now
                kids.push_back({pid, std::string(p)});
            }

            for (auto &[pid, path] : kids) {
                int status = 0;
                waitpid(pid, &status, 0);
                auto buf = llvm::MemoryBuffer::getFile(path);
                if (buf) {
                    llvm::StringRef all = (*buf)->getBuffer();
                    while (!all.empty()) {
                        auto [line, rest] = all.split('\n');
                        all = rest;
                        if (line.trim().empty()) continue;
                        ShardIPC rec;
                        if (!deserializeShardResult(line.str(), rec)) continue;
                        vocabFacts.merge(rec.threadRoles);
                        if (rec.exitCode == 0) ++parsed;
                    }
                }
                llvm::sys::fs::remove(path);
            }
        }
        std::set<std::string> av, fv;
        inferAllocatorVocabulary(vocabFacts, request.config
                                     .allocatorFunctionPatterns, av, fv);
        result.threadRoleFacts.merge(vocabFacts);
        result.coverage.distinctFunctions = vocabFacts.definedFunctions.size();
        std::set<std::string> mv;
        inferMappingVocabulary(vocabFacts,
                               request.config.mappingFunctionPatterns, mv);
        analysisConfig.derivedMappingNames = mv;
        std::set<std::string> lv, uv;
        size_t seededLock = 0, seededUnlock = 0;
        inferLockVocabulary(vocabFacts, request.config.lockFunctionPatterns,
                            request.config.unlockFunctionPatterns, lv, uv,
                            &seededLock, &seededUnlock);
        std::set<std::string> tip;
        inferThreadIdentParams(vocabFacts, tip);
        analysisConfig.threadIdentParams = tip;
        analysisConfig.derivedLockNames = lv;
        analysisConfig.derivedUnlockNames = uv;
        // Names, not counts: a count cannot be diffed and cannot be checked.
        // The full set including seeds, since what matters to a reader is the
        // vocabulary the scan actually applied.
        result.metadata.derivedAllocators.assign(av.begin(), av.end());
        result.metadata.derivedFreers.assign(fv.begin(), fv.end());
        result.metadata.derivedLocks.assign(lv.begin(), lv.end());
        result.metadata.derivedUnlocks.assign(uv.begin(), uv.end());
        result.metadata.derivedMappings.assign(mv.begin(), mv.end());
        // Appended to the configured list so every consumer picks them up:
        // CacheLineMap, EscapeAnalysis and the four false-sharing rules all
        // read atomicTypeNames already and need no change.
        for (const auto &t : vocabFacts.atomicTypes)
            analysisConfig.atomicTypeNames.push_back(t);
        result.metadata.derivedAtomicTypes.assign(vocabFacts.atomicTypes.begin(),
                                                  vocabFacts.atomicTypes.end());

        analysisConfig.derivedAllocatorNames = av;
        analysisConfig.derivedFreeNames = fv;
        // Every derived vocabulary is reported, not just the allocator one.
        // A config list is at least readable; an inference that says nothing
        // about what it concluded is less inspectable than the thing it
        // replaced. Counts exclude the seeds so the number is what this
        // codebase contributed.
        auto beyondSeeds = [](const std::set<std::string> &s, size_t seeds) {
            return s.size() > seeds ? s.size() - seeds : 0;
        };
        report("vocabulary",
               std::to_string(parsed) + "/" + std::to_string(sources.size()) +
               " TU(s) prescanned clean, " +
               std::to_string(beyondSeeds(av, 14)) + " allocator, " +
               std::to_string(beyondSeeds(fv, 16)) + " release, " +
               std::to_string(beyondSeeds(lv, seededLock)) + " lock, " +
               std::to_string(beyondSeeds(uv, seededUnlock)) + " unlock, " +
               std::to_string(beyondSeeds(mv, 4)) +
               " mapping name(s) derived" +
               (vocabCache.enabled()
                    ? ", " + std::to_string(sources.size() - toParse.size()) +
                          " from cache"
                    : std::string()));

        // An undecidable wrapper and one that decided "no" are otherwise the
        // same silence.
        const auto opaque = unresolvedVocabularyBoundaries(vocabFacts, av, fv);
        result.metadata.undecidedWrappers = opaque;
        if (!opaque.empty()) {
            std::string names;
            for (size_t i = 0; i < opaque.size() && i < 5; ++i)
                names += (i ? ", " : "") + opaque[i];
            if (opaque.size() > 5)
                names += ", and " + std::to_string(opaque.size() - 5) + " more";
            report("vocabulary",
                   std::to_string(opaque.size()) +
                   " wrapper(s) undecided, forwarding to a callee with no "
                   "definition in this scan: " + names +
                   ". Add to allocator_function_patterns if they allocate or "
                   "release");
        }
    }

    int toolRet = 0;

    unsigned completedTUs = 0;
    const unsigned totalTUs = static_cast<unsigned>(sources.size());

    // Analysis results depend on the config the rules read and on the derived
    // vocabulary, so both are in the key; the prepass cache uses a different
    // one and survives edits that invalidate these.
    TUCache tuCache(analysisConfig.cacheDir.empty()
                        ? std::string()
                        : analysisConfig.cacheDir + "/tu");
    const std::string cfgDigest =
        tuCache.enabled() ? configDigest(analysisConfig) : std::string();
    auto tuKey = [&](const std::string &src) {
        auto cmds = compDB.getCompileCommands(src);
        return TUCache::keyFor(src,
                               cmds.empty() ? std::vector<std::string>()
                                            : cmds.front().CommandLine,
                               cfgDigest);
    };
    auto absorb = [&](const ShardIPC &r) {
        result.diagnostics.insert(result.diagnostics.end(),
                                  r.diagnostics.begin(), r.diagnostics.end());
        failedTUsDetailed.insert(failedTUsDetailed.end(),
                                 r.failedTUs.begin(), r.failedTUs.end());
        mergeEscapeSummaries(result.escapeSummary, r.escapeSummary);
        result.memory.merge(r.memory);
        result.threadRoleFacts.merge(r.threadRoles);
        mergeStripedArrays(result.stripedArrays, r.striped);
        result.coverage.merge(r.coverage);
    };

    std::vector<std::string> pending;
    unsigned tuCacheHits = 0;
    for (const auto &src : sources) {
        std::string rec;
        ShardIPC r;
        if (tuCache.enabled() && tuCache.lookup(tuKey(src), rec) &&
            deserializeShardResult(rec, r)) {
            absorb(r);
            ++tuCacheHits;
            ++completedTUs;
            continue;
        }
        pending.push_back(src);
    }
    if (tuCache.enabled())
        report("cache", std::to_string(tuCacheHits) + "/" +
               std::to_string(sources.size()) + " TU(s) served from cache");
    const std::vector<std::string> &work = pending;

    if (jobs <= 1 || work.size() <= 1) {
        // Sequential path: per-TU crash isolation.
        for (const auto &src : work) {
            std::vector<std::string> singleTU = {src};
            std::vector<Diagnostic> tuDiags;
            LshazActionFactory factory(
                analysisConfig, tuDiags, profileHotFuncs);

            llvm::CrashRecoveryContext CRC;
            bool crashed = !CRC.RunSafely([&]() {
                clang::tooling::ClangTool tool(compDB, singleTU);
                addResourceDirAdjuster(tool, compDB, src);
                int ret = tool.run(&factory);
                if (ret != 0) toolRet = ret;
            });

            if (crashed) {
                FailedTU ftu;
                ftu.file = src;
                ftu.error = "process crash during analysis";
                failedTUsDetailed.push_back(ftu);
                llvm::errs() << "lshaz: [crash] " << src
                             << " (recovered, continuing)\n";
            } else {
                auto &ff = factory.failedTUs();
                failedTUsDetailed.insert(failedTUsDetailed.end(),
                    ff.begin(), ff.end());
                // Only a clean run is stored, for the same reason the prepass
                // does not cache crashes: a replayed crash is never retried.
                if (tuCache.enabled() && ff.empty() && !factory.deps().empty())
                    tuCache.store(tuKey(src), factory.deps(),
                                  serializeShardResult(
                                      0, {}, tuDiags, factory.escapeSummary(),
                                      factory.threadRoles(),
                                      factory.stripedArrays(),
                                      factory.coverage(), factory.memory(),
                                      src));
            }
            result.diagnostics.insert(result.diagnostics.end(),
                std::make_move_iterator(tuDiags.begin()),
                std::make_move_iterator(tuDiags.end()));
            mergeEscapeSummaries(result.escapeSummary, factory.escapeSummary());
            result.memory.merge(factory.memory());
            result.threadRoleFacts.merge(factory.threadRoles());
            mergeStripedArrays(result.stripedArrays, factory.stripedArrays());
            result.coverage.merge(factory.coverage());
            ++completedTUs;
            report("progress", std::to_string(completedTUs) + "/" +
                   std::to_string(totalTUs));
        }
    } else {
        // Fork per shard, not threads: ClangTool's global mutable state
        // (llvm::cl option tables, CrashRecoveryContext signal handlers,
        // FileManager stat caches) is not thread-safe, and a separate address
        // space is the only isolation that holds. Children serialize to temp
        // files the parent reads after waitpid().
        std::vector<std::vector<std::string>> shards(jobs);
        for (size_t i = 0; i < work.size(); ++i)
            shards[i % jobs].push_back(work[i]);

        struct ChildSlot {
            pid_t pid = -1;
            std::string ipcPath;
            unsigned shardIdx = 0;
        };
        std::vector<ChildSlot> children;
        children.reserve(jobs);

        for (unsigned j = 0; j < jobs; ++j) {
            if (shards[j].empty()) continue;

            // O_EXCL with a random component, and the child inherits the
            // descriptor rather than reopening by name: a predictable path
            // opened for truncation is a symlink clobber on a shared host.
            int ipcFD = -1;
            llvm::SmallString<128> ipcPath;
            if (auto ec = llvm::sys::fs::createTemporaryFile(
                    "lshaz-shard", "json", ipcFD, ipcPath)) {
                llvm::errs() << "lshaz: could not create IPC file for shard "
                             << j << ": " << ec.message() << "\n";
                for (const auto &src : shards[j]) {
                    FailedTU ftu;
                    ftu.file = src;
                    ftu.error = "IPC file creation failed: " + ec.message();
                    failedTUsDetailed.push_back(ftu);
                }
                toolRet = 1;
                continue;
            }

            pid_t pid = fork();
            if (pid < 0) {
                // The shard's TUs are unanalyzed; they must be accounted as
                // failed or the scan reports coverage it never had.
                llvm::errs() << "lshaz: fork() failed for shard " << j
                             << ": " << strerror(errno) << "\n";
                for (const auto &src : shards[j]) {
                    FailedTU ftu;
                    ftu.file = src;
                    ftu.error = std::string("fork() failed: ") + strerror(errno);
                    failedTUsDetailed.push_back(ftu);
                }
                toolRet = 1;
                continue;
            }

            if (pid == 0) {
                // Deterministic stand-in for the OOM killer, which cannot be
                // summoned on demand. Announced on stderr so an injected run
                // is never mistaken for a real one. "<shard>" kills before any
                // TU; "<shard>:<n>" kills after n, exercising partial recovery.
                unsigned faultShard = ~0u, faultAfterTUs = 0;
                if (const char *f = ::getenv("LSHAZ_FAULT_KILL_SHARD")) {
                    faultShard = static_cast<unsigned>(atoi(f));
                    if (const char *colon = ::strchr(f, ':'))
                        faultAfterTUs = static_cast<unsigned>(atoi(colon + 1));
                }
                auto maybeFault = [&](unsigned done) {
                    if (faultShard != j || done != faultAfterTUs) return;
                    llvm::errs() << "lshaz: FAULT INJECTION active, killing "
                                    "shard " << j << " after " << done
                                 << " TU(s)\n";
                    ::raise(SIGKILL);
                };
                maybeFault(0);

                if (shardMemoryLimitMB != 0) {
                    struct rlimit rl;
                    rl.rlim_cur = static_cast<rlim_t>(shardMemoryLimitMB)
                                  << 20;
                    rl.rlim_max = rl.rlim_cur;
                    if (::setrlimit(RLIMIT_AS, &rl) != 0) {
                        llvm::errs() << "lshaz: shard " << j
                                     << " could not set its memory cap: "
                                     << strerror(errno) << "\n";
                        _exit(kShardIPCWriteFailed);
                    }
                    // Turn allocation failure into a named exit rather than a
                    // bad_alloc unwinding through Clang into an opaque crash.
                    llvm::install_bad_alloc_error_handler(
                        [](void *, const char *reason, bool) {
                            llvm::errs() << "lshaz: shard exhausted its memory "
                                            "cap: " << reason << "\n";
                            _exit(kShardMemoryExhausted);
                        });
                    std::set_new_handler([]() {
                        llvm::errs() << "lshaz: shard exhausted its memory "
                                        "cap in operator new\n";
                        _exit(kShardMemoryExhausted);
                    });
                }
                llvm::CrashRecoveryContext::Enable();

                // One record per TU, flushed as it completes, so a fatal TU
                // costs only itself. Records are newline-delimited: a torn
                // tail is discardable and the parent can name exactly which
                // TUs went unreached.
                llvm::raw_fd_ostream out(ipcFD, /*shouldClose=*/true);

                int childRet = 0;
                unsigned tusDone = 0;
                for (const auto &src : shards[j]) {
                    std::vector<std::string> singleTU = {src};
                    std::vector<Diagnostic> tuDiags;
                    std::vector<FailedTU> tuFailed;
                    LshazActionFactory factory(
                        analysisConfig, tuDiags, profileHotFuncs);

                    int tuRet = 0;
                    llvm::CrashRecoveryContext CRC;
                    bool ok = CRC.RunSafely([&]() {
                        clang::tooling::ClangTool tool(compDB, singleTU);
                        addResourceDirAdjuster(tool, compDB, src);
                        int ret = tool.run(&factory);
                        if (ret != 0) tuRet = ret;
                    });
                    if (!ok) {
                        FailedTU ftu;
                        ftu.file = src;
                        ftu.error = "process crash during analysis";
                        tuFailed.push_back(ftu);
                    } else {
                        auto &ff = factory.failedTUs();
                        tuFailed.insert(tuFailed.end(), ff.begin(), ff.end());
                    }
                    if (tuRet != 0) childRet = tuRet;

                    const std::string rec = serializeShardResult(
                        tuRet, tuFailed, tuDiags, factory.escapeSummary(),
                        factory.threadRoles(), factory.stripedArrays(),
                        factory.coverage(), factory.memory(), src);
                    // Written by the child that produced it: the parent never
                    // sees the dependency list, and shipping it over IPC would
                    // pay for it twice.
                    if (tuCache.enabled() && tuRet == 0 && tuFailed.empty() &&
                        !factory.deps().empty())
                        tuCache.store(tuKey(src), factory.deps(), rec);
                    out << rec << "\n";
                    out.flush();
                    if (out.has_error()) {
                        llvm::errs() << "lshaz: shard " << j
                                     << " failed writing IPC to " << ipcPath
                                     << ": " << out.error().message() << "\n";
                        _exit(kShardIPCWriteFailed);
                    }
                    maybeFault(++tusDone);
                }

                out.close();
                _exit(childRet != 0 ? 1 : 0);
            }

            // --- Parent ---
            ::close(ipcFD);   // the child owns it now
            children.push_back({pid, std::string(ipcPath), j});
        }

        // Reap all children. A shard is accounted for in exactly one way:
        // its IPC parsed, or every TU it owned is marked failed. Any path
        // that does neither converts a lost shard into silently missing
        // coverage that reads identically to a clean scan.
        for (auto &child : children) {
            int status = 0;
            std::string lostReason;
            if (waitpid(child.pid, &status, 0) < 0) {
                lostReason = std::string("waitpid() failed: ") + strerror(errno);
            } else if (WIFSIGNALED(status)) {
                // Signalled children are unrecoverable even if a partial IPC
                // file exists: SIGKILL (the OOM killer's signal) can land
                // mid-write, leaving a prefix that may still parse.
                lostReason = "killed by signal " +
                             std::to_string(WTERMSIG(status));
            } else if (WIFEXITED(status) &&
                       WEXITSTATUS(status) == kShardIPCWriteFailed) {
                lostReason = "could not write its IPC file";
            } else if (WIFEXITED(status) &&
                       WEXITSTATUS(status) == kShardMemoryExhausted) {
                lostReason = "exceeded its " +
                             std::to_string(shardMemoryLimitMB) +
                             " MiB memory cap (raise --memory-limit-mb or "
                             "lower --jobs)";
            }

            // Records land one per line as each TU finishes, so a shard that
            // died still hands back everything it completed. Whatever is
            // missing is named individually rather than condemning the shard.
            std::unordered_set<std::string> covered;
            {
                auto buf = llvm::MemoryBuffer::getFile(child.ipcPath);
                if (!buf) {
                    if (lostReason.empty())
                        lostReason = "left no IPC file: " +
                                     buf.getError().message();
                } else {
                    llvm::StringRef body = (*buf)->getBuffer();
                    size_t nl;
                    while ((nl = body.find('\n')) != llvm::StringRef::npos) {
                        llvm::StringRef line = body.take_front(nl);
                        body = body.drop_front(nl + 1);
                        if (line.empty()) continue;
                        ShardIPC rec;
                        if (!deserializeShardResult(line.str(), rec)) {
                            if (lostReason.empty())
                                lostReason = "wrote unparseable IPC";
                            continue;
                        }
                        if (!rec.src.empty()) covered.insert(rec.src);
                        if (rec.exitCode != 0) toolRet = rec.exitCode;
                        result.diagnostics.insert(result.diagnostics.end(),
                            std::make_move_iterator(rec.diagnostics.begin()),
                            std::make_move_iterator(rec.diagnostics.end()));
                        failedTUsDetailed.insert(failedTUsDetailed.end(),
                            rec.failedTUs.begin(), rec.failedTUs.end());
                        mergeEscapeSummaries(result.escapeSummary,
                                             rec.escapeSummary);
                        result.memory.merge(rec.memory);
                        result.threadRoleFacts.merge(rec.threadRoles);
                        mergeStripedArrays(result.stripedArrays, rec.striped);
                        result.coverage.merge(rec.coverage);
                    }
                    // A tail without its newline is a torn write, not a record.
                    if (!body.empty() && lostReason.empty())
                        lostReason = "IPC ends mid-record";
                }
            }

            std::vector<std::string> unreached;
            for (const auto &src : shards[child.shardIdx])
                if (!covered.count(src)) unreached.push_back(src);

            if (!unreached.empty()) {
                if (lostReason.empty())
                    lostReason = "exited without reporting every TU";
                llvm::errs() << "lshaz: shard " << child.shardIdx << ": "
                             << lostReason << "; " << unreached.size() << " of "
                             << shards[child.shardIdx].size()
                             << " TU(s) unanalyzed ("
                             << covered.size() << " recovered)\n";
                for (const auto &src : unreached) {
                    FailedTU ftu;
                    ftu.file = src;
                    ftu.error = "shard lost: " + lostReason;
                    failedTUsDetailed.push_back(ftu);
                }
                toolRet = 1;
            } else if (!lostReason.empty()) {
                // Every TU reported, but the shard still ended badly. Say so.
                llvm::errs() << "lshaz: shard " << child.shardIdx << ": "
                             << lostReason
                             << "; all TU(s) recovered nonetheless\n";
                toolRet = 1;
            }
            llvm::sys::fs::remove(child.ipcPath);
            completedTUs += static_cast<unsigned>(shards[child.shardIdx].size());
            report("progress", std::to_string(completedTUs) + "/" +
                   std::to_string(totalTUs));
        }
    }

    llvm::CrashRecoveryContext::Disable();

    // Canonicalize diagnostic order before any order-dependent pass.
    // In parallel mode, diagnostics arrive in non-deterministic order
    // (thread scheduling). Sorting by a stable key ensures cross-TU
    // suppression, dedup, and precision budget produce identical output
    // regardless of thread count or execution order.
    std::sort(result.diagnostics.begin(), result.diagnostics.end(),
              [](const Diagnostic &a, const Diagnostic &b) {
                  if (a.ruleID != b.ruleID) return a.ruleID < b.ruleID;
                  if (a.location.file != b.location.file)
                      return a.location.file < b.location.file;
                  if (a.location.line != b.location.line)
                      return a.location.line < b.location.line;
                  if (a.location.column != b.location.column)
                      return a.location.column < b.location.column;
                  if (a.functionName != b.functionName)
                      return a.functionName < b.functionName;
                  return diagnosticContentLess(a, b);
              });

    // FL040 reduce phase: aggregate per-TU write counts into a global verdict.
    // Shards emitted raw facts (tu_write_count, has_init). We sum writes across
    // all TUs for each (var, type) and apply the write-once threshold globally.
    // This must run before dedup so all duplicate instances get reclassified
    // consistently. Dedup then collapses them to a single canonical instance.
    {
        // Accumulate: key = "var|type", value = {total_writes, any_has_init}
        struct FL040Agg {
            unsigned totalWrites = 0;
            unsigned loopWrites = 0;
            bool anyHasInit = false;
        };
        std::unordered_map<std::string, FL040Agg> fl040Agg;

        for (const auto &d : result.diagnostics) {
            if (d.ruleID != "FL040") continue;
            auto varIt = d.structuralEvidence.find("var");
            auto typeIt = d.structuralEvidence.find("type");
            if (varIt == d.structuralEvidence.end()) continue;
            std::string key = varIt->second;
            if (typeIt != d.structuralEvidence.end())
                key += "|" + typeIt->second;

            auto wcIt = d.structuralEvidence.find("tu_write_count");
            auto lwIt = d.structuralEvidence.find("tu_loop_writes");
            auto hiIt = d.structuralEvidence.find("has_init");
            unsigned wc = 0, lw = 0;
            if (wcIt != d.structuralEvidence.end())
                wc = static_cast<unsigned>(std::stoul(wcIt->second));
            if (lwIt != d.structuralEvidence.end())
                lw = static_cast<unsigned>(std::stoul(lwIt->second));
            bool hi = (hiIt != d.structuralEvidence.end()
                       && hiIt->second == "yes");

            auto &agg = fl040Agg[key];
            agg.totalWrites += wc;
            agg.loopWrites += lw;
            if (hi) agg.anyHasInit = true;
        }

        // Reclassify each FL040 diagnostic based on global verdict.
        for (auto &d : result.diagnostics) {
            if (d.ruleID != "FL040") continue;
            auto varIt = d.structuralEvidence.find("var");
            auto typeIt = d.structuralEvidence.find("type");
            if (varIt == d.structuralEvidence.end()) continue;
            std::string key = varIt->second;
            if (typeIt != d.structuralEvidence.end())
                key += "|" + typeIt->second;

            auto it = fl040Agg.find(key);
            if (it == fl040Agg.end()) continue;

            const auto &agg = it->second;
            // On the global sum rather than a single TU's. One site inside a
            // loop is one site, not one write, so it is never write-once.
            bool writeOnce = false;
            if (agg.loopWrites == 0) {
                if (agg.anyHasInit && agg.totalWrites == 0)
                    writeOnce = true;
                else if (agg.totalWrites <= 1)
                    writeOnce = true;
            }

            // Replace per-TU metadata with global verdict.
            d.structuralEvidence.erase("tu_write_count");
            d.structuralEvidence.erase("tu_loop_writes");
            d.structuralEvidence.erase("has_init");
            d.structuralEvidence["write_once"] = writeOnce ? "yes" : "no";
            d.structuralEvidence["global_write_count"] =
                std::to_string(agg.totalWrites);
            d.structuralEvidence["global_loop_writes"] =
                std::to_string(agg.loopWrites);

            bool atomicVar =
                d.structuralEvidence.count("atomics") &&
                d.structuralEvidence.at("atomics") == "yes";

            if (writeOnce) {
                d.severity = Severity::Informational;
                d.confidence = 0.30;
                d.evidenceTier = EvidenceTier::Speculative;
                d.escalations.push_back(
                    "write-once (global): across all TUs, at most one write "
                    "site, negligible runtime contention");
            } else if (!atomicVar && agg.totalWrites <= 1) {
                // single in-loop site on a plain type: repeated writes but
                // one write path; concurrent writers would be a data race,
                // not a latency hazard.
                d.severity = Severity::Informational;
                d.confidence = 0.35;
                d.evidenceTier = EvidenceTier::Speculative;
                d.escalations.push_back(
                    "single write site (in a loop) on a non-atomic global: "
                    "one write path, no multi-writer topology");
            } else if (d.severity == Severity::Critical &&
                       agg.loopWrites == 0 && agg.totalWrites < 4) {
                // Critical means sustained RFO pressure: a write in a loop,
                // or write responsibility spread over >=4 sites. 2-3 flat
                // sites is the start/stop lifecycle signature.
                d.severity = Severity::High;
                d.escalations.push_back(
                    "atomic global with " + std::to_string(agg.totalWrites) +
                    " flat write site(s) across all TUs, none in a loop: "
                    "lifecycle-signaling pattern, not sustained contention");
            }
        }
    }

    // Cache pruning runs once per scan, after both passes have written.
    // Entries are content-keyed, so a survivor is never stale and this is a
    // disk-space bound rather than a correctness mechanism.
    if (tuCache.enabled() && request.config.cacheMaxMB)
        TUCache::prune(request.config.cacheDir,
                       static_cast<uint64_t>(request.config.cacheMaxMB) << 20);

    if (request.ir.enabled && sources.size() > failedTUsDetailed.size()) {
        report("ir", "IR emission and analysis");
        std::unordered_set<std::string> failedFiles;
        failedFiles.reserve(failedTUsDetailed.size());
        for (const auto &ftu : failedTUsDetailed)
            failedFiles.insert(ftu.file);
        runIRPass(request, compDB, sources, failedFiles,
                  result.diagnostics, result.metadata, optRemarks,
                  remarkFilesFailed);
    }

    // Cross-TU escape suppression using aggregated per-type escape summaries.
    if (sources.size() > 1) {
        report("cross_tu",
               std::to_string(result.diagnostics.size()) + " raw finding(s), " +
               std::to_string(result.escapeSummary.size()) + " type(s) in escape summary");
        unsigned crossTUSuppressed = applyCrossTUEscapeSuppression(
            result.diagnostics, result.escapeSummary, result.totalTUsAnalyzed);
        if (crossTUSuppressed > 0)
            report("cross_tu", std::to_string(crossTUSuppressed) +
                   " finding(s) suppressed (no cross-TU escape evidence)");

        SharingRouteVerdict route = applySharingRouteVerdict(
            result.diagnostics, result.escapeSummary);
        if (route.refuted > 0)
            report("cross_tu", std::to_string(route.refuted) +
                   " sharing finding(s) refuted (no shared instance any TU "
                   "reached)");
        if (route.capped > 0)
            report("cross_tu", std::to_string(route.capped) +
                   " sharing finding(s) capped (no shared instance any TU "
                   "reached, writes not observable)");
        if (route.vocabularyDark && (route.capped > 0 || route.refuted > 0))
            report("cross_tu",
                   "no thread route found on any type in this scan: thread "
                   "creation is unrecognized here, so no sharing finding was "
                   "refuted on its absence");
    }

    // Thread-role reduce: verdicts from the merged facts. Runs on the
    // parent's aggregate regardless of jobs count; children never see
    // enough of the graph to classify anything.
    // Derive the project's allocator vocabulary before anything consults it.
    // Config patterns extend the libc seeds rather than carrying the analysis.
    std::set<std::string> allocVocab, freeVocab;
    inferAllocatorVocabulary(result.threadRoleFacts,
                             request.config.allocatorFunctionPatterns,
                             allocVocab, freeVocab);

    result.threadRoles = computeThreadRoles(result.threadRoleFacts,
                                            request.config.threadEntryPatterns,
                                            request.config.mainFunctionPatterns);
    if (!result.threadRoles.functionRoles.empty()) {
        report("thread_roles",
               std::to_string(result.threadRoleFacts.threadEntries.size()) +
               " thread entry point(s), " +
               std::to_string(result.threadRoles.functionRoles.size()) +
               " function(s) attributed");
        unsigned roleEscalated = applyThreadRoleEscalation(
            result.diagnostics, result.threadRoleFacts, result.threadRoles);
        if (roleEscalated > 0)
            report("thread_roles", std::to_string(roleEscalated) +
                   " finding(s) escalated (disjoint writer roles)");

        // FL020's cross-thread-free conjunct. The rule ships it gating and
        // unestablished, which caps every allocation finding at Medium, and
        // only the merged summary can settle it: the allocation and the free
        // are routinely in different TUs, joined here by the allocated type.
        unsigned xfree = 0;
        for (auto &d : result.diagnostics) {
            if (d.ruleID != "FL020")
                continue;
            std::string ty;
            for (const auto &[k, v] : d.structuralEvidence)
                if (k == "allocated_type") { ty = v; break; }
            if (ty.empty() ||
                !result.threadRoles.typeIsFreedCrossThread(
                    result.threadRoleFacts, ty))
                continue;
            // Two claims describe this, and only one moves the grade.
            // severitySupportedByClaims reads a gating claim's supports as a
            // cap and never looks at its established flag, so the arena
            // contention claim is what has to become established; the gating
            // one is updated because the verdict text lists it.
            for (auto &c : d.mechanismClaims) {
                if (c.precondition.rfind("a free on a thread other than", 0) ==
                    0)
                    c.state = ClaimState::Established;
                if (c.gating && c.precondition.rfind("alloc and free", 0) == 0) {
                    c.state = ClaimState::Established;
                    c.precondition = "alloc and free of '" + ty +
                                     "' attributed to disjoint thread roles";
                }
            }
            d.escalations.push_back(
                "cross-TU: every allocation of '" + ty +
                "' happens on one thread role and every free on another, so "
                "the block returns to an arena owned by a different thread, "
                "several times the cost of the same-thread round trip");
            ++xfree;
        }
        // Report the join's reach, not just its hits. Zero established reads
        // identically whether every free is same-thread or no type was ever
        // recorded on both sides, and those call for opposite responses.
        unsigned bothSides = 0, bothAttributed = 0;
        for (const auto &[ty, allocFns] :
             result.threadRoleFacts.allocatorsOfType) {
            auto f = result.threadRoleFacts.freersOfType.find(ty);
            if (f == result.threadRoleFacts.freersOfType.end())
                continue;
            ++bothSides;
            // Disjointness needs every function on both sides attributed: one
            // unknown allocator could hold the freer's role. Counting these
            // separates "the frees really are same-thread" from "the call
            // graph never reached these functions", which want opposite fixes.
            if (result.threadRoles.rolesOf(allocFns) != ROLE_NONE &&
                result.threadRoles.rolesOf(f->second) != ROLE_NONE)
                ++bothAttributed;
        }
        report("alloc_vocab",
               std::to_string(allocVocab.size()) + " allocator name(s) and " +
               std::to_string(freeVocab.size()) +
               " release name(s) inferred from " +
               std::to_string(result.threadRoleFacts.returnForwards.size()) +
               " return-forward and " +
               std::to_string(result.threadRoleFacts.paramForwards.size()) +
               " param-forward edge(s)");
        if (!result.threadRoleFacts.allocatorsOfType.empty())
            report("thread_roles",
                   std::to_string(result.threadRoleFacts.allocatorsOfType
                                      .size()) +
                   " type(s) allocated, " +
                   std::to_string(
                       result.threadRoleFacts.freersOfType.size()) +
                   " freed, " + std::to_string(bothSides) +
                   " with both sides seen, " +
                   std::to_string(bothAttributed) +
                   " fully role-attributed, " + std::to_string(xfree) +
                   " FL020 finding(s) with cross-thread free established");
    }

    // Resolve cross-TU hotness candidates. A TU holding no entry point could
    // not decide, so the map phase deferred rather than answering "cold" from
    // facts it did not have, and this is the only place the whole call graph
    // exists. Hoisted out of the block below because the cross-TU
    // line-sharing join needs it too.
    const auto globalHot = inferGlobalHotness(
        result.threadRoleFacts, request.config.mainFunctionPatterns);
    {
        std::set<std::string> withdrawnFns;
        std::set<std::string> withdrawable;
        for (const auto &r : RuleRegistry::instance().rules())
            if (r->withdrawnWhenNotHot())
                withdrawable.insert(std::string(r->getID()));
        unsigned resolved = 0, dropped = 0;
        for (auto &d : result.diagnostics) {
            if (d.hotness != static_cast<uint8_t>(HotnessSource::Candidate))
                continue;
            auto it = globalHot.find(d.functionName);
            if (it == globalHot.end() && !withdrawable.count(d.ruleID)) {
                d.hotness = static_cast<uint8_t>(HotnessSource::None);
                continue;
            }
            if (it == globalHot.end()) {
                // Never reached from any entry in any TU. This is the verdict
                // the map phase would have reached had it been able to see
                // the whole program.
                d.suppressed = true;
                ++dropped;
                withdrawnFns.insert(d.functionName);
                continue;
            }
            d.hotness = static_cast<uint8_t>(it->second);
            ++resolved;
            for (auto &c : d.mechanismClaims) {
                if (!c.gating || c.effect.rfind("this code runs often", 0) != 0)
                    continue;
                c.effect = std::string("this code runs often enough for the "
                                       "cost to recur (") +
                           hotnessSourceName(it->second) + ", cross-TU)";
                c.supports = hotnessSupportedSeverity(it->second, d.severity);
            }
        }
        result.coverage.functionsWithdrawnCold = withdrawnFns.size();
        if (resolved || dropped)
            report("hotness", std::to_string(resolved) +
                   " cross-TU candidate(s) confirmed hot, " +
                   std::to_string(dropped) + " dropped as cold");

        unsigned fromRemarks = emitOptRemarkFindings(
            result.diagnostics, optRemarks, globalHot,
            request.config.hotFunctionPatterns);
        if (!optRemarks.empty() || remarkFilesFailed)
            report("opt_remarks", std::to_string(fromRemarks) +
                   " finding(s) from " + std::to_string(optRemarks.size()) +
                   " reportable compiler remark(s)" +
                   (remarkFilesFailed
                        ? "; " + std::to_string(remarkFilesFailed) +
                              " remark file(s) ended truncated, coverage "
                              "for those TUs is partial"
                        : std::string()));
    }

    // Monomorphic virtual calls. Nothing overrides the callee anywhere in the
    // program, so the receiver cannot vary and the misprediction term is
    // absent, leaving only the lost inline.
    {
        unsigned mono = 0;
        for (auto &d : result.diagnostics) {
            if (d.suppressed || (d.ruleID != "FL030" && d.ruleID != "FL031"))
                continue;
            auto ev = d.structuralEvidence.find("virtual_call");
            if (ev == d.structuralEvidence.end())
                continue;
            if (result.threadRoleFacts.overriddenVirtuals.count(ev->second))
                continue;
            ++mono;
            d.escalations.push_back(
                "no override of '" + ev->second + "' anywhere in the "
                "program: dispatch is monomorphic, so only the inlining "
                "barrier is paid and not the mispredict");
            for (auto &c : d.mechanismClaims)
                if (c.gating && c.effect.rfind("receiver type varies", 0) == 0)
                    c.supports = Severity::Medium;
        }
        if (mono)
            report("devirt", std::to_string(mono) +
                   " virtual dispatch finding(s) monomorphic program-wide");
    }

    // an already line-aligned type in-tree makes relocation available at
    // zero footprint cost; same index FL092 joins against.
    bool alignedOwnerAvailable = false;
    for (const auto &[tn, sig] : result.escapeSummary)
        if (sig.hasDeliberateLayout) { alignedOwnerAvailable = true; break; }
    MachineModel machineStorage;
    machineStorage.name = request.config.machineName.empty()
                              ? std::string("unspecified")
                              : request.config.machineName;
    machineStorage.lineBytes =
        static_cast<uint32_t>(request.config.cacheLineBytes);
    machineStorage.l1dBytes =
        static_cast<uint32_t>(request.config.l1dSizeBytes);
    machineStorage.cyclesHitmLocal = request.config.cyclesHitmLocal;
    machineStorage.cyclesHitmRemote = request.config.cyclesHitmRemote;
    machineStorage.cyclesDram = request.config.cyclesDram;
    machineStorage.cyclesMispredict = request.config.cyclesMispredict;
    machineStorage.mlpOverlapPct = request.config.mlpOverlapPct;
    const MachineModel *machine = &machineStorage;
    WorkloadModel workload;
    workload.cyclesPerOp = request.config.workloadCyclesPerOp;
    workload.sharers = request.config.workloadSharers;
    const std::string workloadName = request.config.workloadName.empty()
                                         ? std::string("unspecified")
                                         : request.config.workloadName;

    // A store that exists and cannot be read is a hard error. Scanning on
    // through it would apply no correction while the operator believes one
    // is in effect, which is the quietest way to be wrong.
    CostCalibration costCalib;
    if (!request.config.costCalibrationPath.empty()) {
        std::string calErr;
        if (!costCalib.load(request.config.costCalibrationPath, calErr)) {
            llvm::errs() << "lshaz: error: " << calErr << "\n";
            result.status = ScanStatus::ToolError;
            return result;
        }
        if (costCalib.size())
            report("cost_calibration",
                   std::to_string(costCalib.size()) +
                   " measured observation(s) correcting the cost model for " +
                   machineStorage.name + "/" + workloadName);
    }
    const RateModel rates =
        computeRateModel(result.threadRoleFacts,
                         request.config.mainFunctionPatterns);
    if (!rates.perOp.empty())
        report("rate_model", std::to_string(rates.perOp.size()) +
               " function(s) rated relative to the busiest; machine " +
               machine->name +
               (workload.known()
                    ? ""
                    : " (workload_cycles_per_op unset, so cost estimates "
                      "are reported but not graded)"));

    unsigned stripedEmitted = emitStripedArrayFindings(
        result.diagnostics, result.stripedArrays, result.threadRoles,
        request.config.cacheLineBytes, request.config.l1dSizeBytes,
        alignedOwnerAvailable);
    if (stripedEmitted > 0)
        report("striped_arrays", std::to_string(stripedEmitted) +
               " per-thread striped array finding(s)");
    unsigned sweepEmitted = emitAggregationSweepFindings(
        result.diagnostics, result.stripedArrays, result.threadRoles, rates,
        *machine, costCalib, workloadName, workload,
        request.config.cacheLineBytes);
    if (sweepEmitted > 0)
        report("aggregation_sweeps", std::to_string(sweepEmitted) +
               " aggregation sweep finding(s)");

    if (unsigned r = settleStoreRepetition(result.diagnostics,
                                           result.threadRoleFacts))
        report("store_repetition", std::to_string(r / 1000) +
               " redundant-store finding(s) dropped as single-shot, " +
               std::to_string(r % 1000) + " confirmed repeating");

    // Cost model inputs, entirely from configuration. Nothing about any
    // specific part is compiled in, so a target with no measurements gets
    // stand-in terms and says so, rather than inheriting numbers measured
    // on hardware it has nothing to do with.

    // Solve once, on the merged constraint set. Andersen's least fixed point
    // is unique, so this answer does not depend on shard count or arrival
    // order the way an order-controlled pass would.
    result.pointsTo = solvePointsTo(result.memory.constraints);
    result.memoryModel = buildMemoryModel(result.memory, result.pointsTo);
    report("points_to",
           std::to_string(result.memory.constraints.size()) +
           " constraint(s) -> " +
           std::to_string(result.pointsTo.objectsDiscovered) + " object(s); " +
           std::to_string(result.memoryModel.objects.size()) +
           " with accesses, " +
           std::to_string(static_cast<int>(
               result.memoryModel.resolutionRate() * 100)) +
           "% of accesses resolved" +
           (result.pointsTo.truncated
                ? std::string(" (TRUNCATED: lower bound)") : std::string()));

    if (unsigned objShared = applyObjectSharingVerdict(
            result.diagnostics, result.memoryModel, result.threadRoles))
        report("points_to", std::to_string(objShared) +
               " sharing finding(s) established on the object itself");

    const ContentionGraph contention = buildContentionGraph(
        result.escapeSummary, result.threadRoleFacts,
        request.config.cacheLineBytes);
    report("contention_graph",
           std::to_string(contention.linesWithTraffic) + " of " +
           std::to_string(contention.linesConsidered) +
           " modelled cache line(s) carry traffic");

    TrueSharingGates tsGates;
    emitTrueSharingFindings(
        result.diagnostics, contention, result.escapeSummary,
        result.threadRoleFacts, result.threadRoles, globalHot, rates,
        *machine, costCalib, workloadName, workload, tsGates);
    // Reported whether or not anything fired, which is the point.
    report("true_sharing", tsGates.summary());

    if (unsigned n = attachAccessSymbols(result.diagnostics, contention))
        report("access_symbols", std::to_string(n) +
               " finding(s) about a type given the symbols that touch it, so "
               "a hardware profile can be joined to them");

    unsigned crossLine = emitCrossTUSharedLineFindings(
        result.diagnostics, result.escapeSummary, result.threadRoleFacts,
        result.threadRoles, globalHot, rates, *machine, costCalib,
        workloadName, workload, request.config.cacheLineBytes);
    if (crossLine > 0)
        report("shared_lines", std::to_string(crossLine) +
               " cross-TU read/write line-sharing finding(s)");

    if (unsigned costGraded = applyCostVerdict(
            result.diagnostics, result.threadRoleFacts, result.threadRoles,
            rates, *machine, workload, costCalib, workloadName))
        report("cost_model", std::to_string(costGraded) +
               " finding(s) carry an estimated cycles-per-operation");

    // Affinity respect runs before dedup so all duplicates demote alike.
    std::string affinityAPI =
        detectAffinityManagement(result.threadRoleFacts);
    unsigned affinityDemoted =
        applyAffinityRespect(result.diagnostics, affinityAPI);
    if (affinityDemoted > 0)
        report("numa", std::to_string(affinityDemoted) +
               " FL060 finding(s) demoted (explicit affinity via " +
               affinityAPI + ")");

    unsigned pagingDemoted = applyPagingRespect(
        result.diagnostics,
        detectPagingManagement(result.threadRoleFacts));
    if (pagingDemoted > 0)
        report("tlb", std::to_string(pagingDemoted) +
               " FL070 finding(s) demoted (paging policy managed in-tree)");

    // Cross-TU deduplication.
    report("dedup", "");
    deduplicateDiagnostics(result.diagnostics);

    // Interaction synthesis.
    report("interactions", "");
    synthesizeInteractions(result.diagnostics);

    // FL092 precedent join.
    unsigned unapplied = synthesizeUnappliedMitigation(
        result.diagnostics, result.escapeSummary);
    if (unapplied > 0)
        report("interactions", std::to_string(unapplied) +
               " FL092 unapplied-mitigation compound(s)");

    PrecisionBudget budget;
    budget.apply(result.diagnostics);

    // Calibration feedback. A requested store that cannot be read is a
    // hard error: proceeding would emit uncalibrated results while the
    // caller believes otherwise.
    std::unique_ptr<CalibrationFeedbackStore> calStore;
    if (!request.feedback.calibrationStorePath.empty()) {
        calStore = std::make_unique<CalibrationFeedbackStore>(
            request.feedback.calibrationStorePath);
        std::string storeErr;
        if (!calStore->load(storeErr)) {
            llvm::errs() << "lshaz: error: " << storeErr << "\n";
            result.status = ScanStatus::ToolError;
            return result;
        }
    }

    if (calStore) {
        result.suppressedByCalibration =
            applyCalibrationSuppression(result.diagnostics, *calStore);
    }

    // PMU trace feedback.
    if (calStore && (!request.feedback.pmuTracePath.empty() ||
                     !request.feedback.pmuPriorsPath.empty())) {
        report("pmu_feedback", "");
        applyPMUFeedback(request.feedback, result.diagnostics, *calStore);

        // PMU ingestion mutated the store; unpersisted labels calibrate
        // nothing and would silently vanish.
        std::string storeErr;
        if (!calStore->save(storeErr)) {
            llvm::errs() << "lshaz: error: " << storeErr << "\n";
            result.status = ScanStatus::ToolError;
            return result;
        }
    }

    // Refuted preconditions retire findings, before anything grades them.
    //
    // A precondition an evidence source checked and found false is a verdict
    // on the mechanism, not a weaker version of it, so the finding leaves
    // naming what refuted it. This is where the ran-versus-never-ran rule
    // reaches the claim ledger: Unknown survives untouched, and only Refuted
    // withdraws.
    {
        std::map<std::string, unsigned> byRule;
        for (auto &d : result.diagnostics) {
            if (d.suppressed)
                continue;
            const auto *dead = d.refutedPrecondition();
            if (!dead)
                continue;
            d.suppressed = true;
            ++byRule[d.ruleID];
            d.escalations.push_back(
                "withdrawn: '" + dead->precondition + "' is refuted (" +
                (dead->observation.empty() ? std::string("no observation "
                                                         "recorded")
                                           : dead->observation) + ")");
        }
        if (!byRule.empty()) {
            std::string detail;
            unsigned total = 0;
            for (const auto &[rule, n] : byRule) {
                total += n;
                detail += (detail.empty() ? "" : " ") + rule + "=" +
                          std::to_string(n);
            }
            result.withdrawnByRefutation = total;
            report("refuted", std::to_string(total) +
                   " finding(s) withdrawn on a refuted precondition; " + detail);
        }
    }

    // A finding may not outrank the mechanism claims it established. Rules
    // declaring no claims are unconstrained; where a rule does declare them
    // this holds by construction at output, so no future rule can reintroduce
    // the violation.
    std::map<std::string, std::pair<unsigned, unsigned>> bindStats; // {bound, total}
    std::map<std::string, long> slackSum;
    for (auto &d : result.diagnostics) {
        if (d.suppressed || d.mechanismClaims.empty())
            continue;
        Severity ceiling = d.severitySupportedByClaims();
        auto &st = bindStats[d.ruleID];
        ++st.second;
        slackSum[d.ruleID] +=
            static_cast<int>(d.severity) - static_cast<int>(ceiling);
        if (d.severity <= ceiling)
            continue;
        ++st.first;
        d.escalations.push_back(
            "severity clamped from " + std::string(severityToString(d.severity)) +
            " to " + std::string(severityToString(ceiling)) +
            ": the effect justifying the higher grade has an unestablished "
            "precondition");
        d.severity = ceiling;
    }
    if (!bindStats.empty()) {
        unsigned boundAll = 0, totalAll = 0;
        std::string detail;
        for (const auto &[rule, st] : bindStats) {
            boundAll += st.first;
            totalAll += st.second;
            if (st.first == 0)
                continue;   // silent rules are summarised, not enumerated
            detail += (detail.empty() ? "" : " ") + rule + "=" +
                      std::to_string(st.first) + "/" +
                      std::to_string(st.second);
        }
        report("claims", std::to_string(boundAll) + "/" +
               std::to_string(totalAll) + " finding(s) clamped by their claims" +
               (detail.empty() ? " (no rule's lattice bound)" : "; " + detail));
    }

    // A finding outside the scanned tree is third-party by construction.
    // Toolchain and dependency headers reached through -I rather than
    // -isystem are analyzed like project code and are not skipped by the
    // vendored-path patterns, which only match directories inside the
    // project.
    if (!request.workingDirectory.empty()) {
        llvm::SmallString<256> rootBuf(request.workingDirectory);
        llvm::sys::fs::make_absolute(rootBuf);
        // "." makes absolute as "<cwd>/.", which prefix-matches nothing.
        llvm::sys::path::remove_dots(rootBuf, /*remove_dot_dot=*/true);
        std::string root(rootBuf.str());
        if (!root.empty() && root.back() != '/')
            root += '/';
        for (auto &d : result.diagnostics) {
            if (d.suppressed || d.location.file.empty())
                continue;
            if (d.location.file.rfind(root, 0) == 0)
                continue;
            d.suppressed = true;
            ++result.outOfTreeSuppressed;
        }
    }

    filterAndSort(request.filter, result.diagnostics);

    // Header fingerprint detection: identify missing header patterns.
    std::map<std::string, unsigned> missingHeaderCounts;
    for (const auto &ftu : failedTUsDetailed)
        if (!ftu.missingHeader.empty())
            ++missingHeaderCounts[ftu.missingHeader];

    // Emit warnings for headers missing from >= 3 TUs. B001 reports a
    // broken scan, so it bypasses severity/evidence filters by design,
    // but it must not break the sorted-output contract (re-sort below).
    bool b001Emitted = false;
    for (const auto &[header, count] : missingHeaderCounts) {
        if (count >= 3) {
            Diagnostic diag;
            diag.ruleID = "B001";
            diag.severity = Severity::Medium;
            diag.confidence = 1.0;
            diag.evidenceTier = EvidenceTier::Speculative;
            diag.location.file = "<pipeline>";
            diag.location.line = 0;
            std::ostringstream msg;
            msg << "Header '" << header << "' is missing in " << count
                << " TUs. This usually indicates the project needs a full build "
                   "before scanning (custom_target, configure_file).";
            diag.title = msg.str();
                diag.structuralEvidence["missing_header"] = header;
            diag.structuralEvidence["tu_count"] = std::to_string(count);
            result.diagnostics.push_back(std::move(diag));
            b001Emitted = true;
        }
    }
    if (b001Emitted)
        std::sort(result.diagnostics.begin(), result.diagnostics.end(),
                  outputOrder);

    // Extract file paths for compatibility with existing metadata/failedTUs.
    result.failedTUs.clear();
    result.failedTUErrors.clear();
    result.failedTUs.reserve(failedTUsDetailed.size());
    result.failedTUErrors.reserve(failedTUsDetailed.size());
    for (const auto &ftu : failedTUsDetailed) {
        result.failedTUs.push_back(ftu.file);
        result.failedTUErrors.push_back(
            ftu.error.empty() ? "unspecified" : ftu.error);
    }

    // Summary counts.
    result.totalTUsFailed = static_cast<unsigned>(result.failedTUs.size());
    result.metadata.totalTUs = result.totalTUsAnalyzed;
    result.metadata.failedTUCount = result.totalTUsFailed;
    result.metadata.failedTUs = result.failedTUs;
    result.metadata.failedTUErrors = result.failedTUErrors;

    bool parseError = (toolRet != 0 || result.totalTUsFailed > 0);
    bool hasFindings = !result.diagnostics.empty();

    if (parseError && hasFindings)
        result.status = ScanStatus::Findings;
    else if (parseError)
        result.status = ScanStatus::ParseError;
    else if (hasFindings)
        result.status = ScanStatus::Findings;
    else
        result.status = ScanStatus::Clean;

    return result;
}

} // namespace lshaz
