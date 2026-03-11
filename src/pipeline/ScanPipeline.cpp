// SPDX-License-Identifier: Apache-2.0
#include "lshaz/pipeline/ScanPipeline.h"
#include "lshaz/pipeline/AbsolutePathCompilationDatabase.h"
#include "lshaz/pipeline/CompileDBResolver.h"
#include "lshaz/pipeline/SourceFilter.h"

#include "lshaz/analysis/LshazAction.h"
#include "lshaz/core/DiagnosticDedup.h"
#include "lshaz/core/DiagnosticInteraction.h"
#include "lshaz/core/PerfProfileParser.h"
#include "lshaz/core/PrecisionBudget.h"
#include "lshaz/core/Version.h"
#include "lshaz/hypothesis/CalibrationFeedback.h"
#include "lshaz/hypothesis/HypothesisConstructor.h"
#include "lshaz/hypothesis/PMUTraceFeedback.h"
#include "lshaz/ir/DiagnosticRefiner.h"
#include "lshaz/ir/IRAnalyzer.h"

#include <clang/Basic/Version.inc>
#include <clang/Tooling/ArgumentsAdjusters.h>
#include <clang/Tooling/CompilationDatabase.h>
#include <clang/Tooling/JSONCompilationDatabase.h>
#include <clang/Tooling/Tooling.h>
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
#include <future>
#include <memory>
#include <mutex>
#include <semaphore>
#include <string>
#include <thread>
#include <vector>

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

struct IRJob {
    std::string srcPath;
    std::string compilerPath;
    std::vector<std::string> argv;
    std::string irFile;
    std::string errFile;
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
    auto resolvedOrErr = llvm::sys::findProgramByName(dbCompiler);
    if (resolvedOrErr && llvm::sys::fs::can_execute(*resolvedOrErr))
        return *resolvedOrErr;

    for (const char *fallback : {"clang++", "clang++-18",
                                  "clang++-17", "clang++-16"}) {
        auto fb = llvm::sys::findProgramByName(fallback);
        if (fb && llvm::sys::fs::can_execute(*fb))
            return *fb;
    }
    return {};
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
        std::vector<Diagnostic> &diagnostics,
        ExecutionMetadata &meta) {

    IRAnalyzer irAnalyzer;
    std::string optLevel = "-" + req.ir.optLevel;

    std::vector<IRJob> jobs;

    for (const auto &srcPath : sources) {
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

        for (const auto &cmd : cmds) {
            const auto &args = cmd.CommandLine;
            for (size_t i = 1; i < args.size(); ++i) {
                if (args[i] == "-c")
                    continue;
                if (args[i] == "-o" && i + 1 < args.size()) {
                    ++i;
                    continue;
                }
                if (args[i] == srcPath)
                    continue;
                argv.push_back(args[i]);
            }
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
        llvm::SmallString<128> irPath(tmpDir), errPath(tmpDir);
        llvm::sys::path::append(irPath,
            "lshaz-" + std::string(hashStr) + ".ll");
        llvm::sys::path::append(errPath,
            "lshaz-" + std::string(hashStr) + ".err");

        bool cached = req.ir.cacheEnabled && llvm::sys::fs::exists(irPath);

        argv.push_back("-o");
        argv.push_back(std::string(irPath));
        argv.push_back(srcPath);

        jobs.push_back({srcPath, compilerPath, std::move(argv),
                        std::string(irPath), std::string(errPath), cached});

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
    std::counting_semaphore<> sem(shardWorkers);

    struct ShardResult {
        IRAnalyzer analyzer;
        std::vector<std::pair<size_t, IRResult>> jobResults;
    };

    std::vector<std::future<ShardResult>> futures;
    futures.reserve(shards.size());

    for (const auto &shard : shards) {
        futures.push_back(std::async(std::launch::async,
            [&sem, &jobs](size_t begin, size_t end) -> ShardResult {
                sem.acquire();
                ShardResult sr;

                for (size_t i = begin; i < end; ++i)
                    sr.jobResults.push_back({i, emitOneIR(jobs[i])});

                llvm::LLVMContext llvmCtx;
                for (const auto &[idx, result] : sr.jobResults) {
                    if (result.exitCode == 0) {
                        llvm::SMDiagnostic parseErr;
                        auto mod = llvm::parseIRFile(
                            jobs[idx].irFile, parseErr, llvmCtx);
                        if (mod)
                            sr.analyzer.analyzeModule(*mod);
                    }
                }

                sem.release();
                return sr;
            },
            shard.begin, shard.end));
    }

    for (auto &future : futures) {
        auto sr = future.get();
        for (const auto &[idx, result] : sr.jobResults) {
            if (result.exitCode != 0) {
                auto errBuf = llvm::MemoryBuffer::getFile(jobs[idx].errFile);
                if (errBuf && !(*errBuf)->getBuffer().empty()) {
                    llvm::errs() << "lshaz: IR emission failed for "
                                 << jobs[idx].srcPath << ":\n"
                                 << (*errBuf)->getBuffer() << "\n";
                }
            }
            if (!jobs[idx].cached && result.exitCode != 0)
                llvm::sys::fs::remove(jobs[idx].irFile);
            llvm::sys::fs::remove(jobs[idx].errFile);
        }
        irAnalyzer.mergeFrom(std::move(sr.analyzer));
    }

    if (!irAnalyzer.profiles().empty()) {
        DiagnosticRefiner refiner(irAnalyzer.profiles());
        refiner.refine(diagnostics);
    }
}

static unsigned applyCalibrationSuppression(
        const FeedbackOptions &fb,
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

// Cross-TU escape suppression: diagnostics that rely on thread_escape=true
// but have atomics=no are likely false positives when the type only appears
// in a single TU. Must be called BEFORE dedup so that duplicate diagnostics
// from multiple TUs are still present (multiplicity > 1 = multi-TU evidence).
static unsigned applyCrossTUEscapeSuppression(
        std::vector<Diagnostic> &diagnostics,
        unsigned totalTUs) {
    if (totalTUs <= 1)
        return 0;

    // Count how many times each (ruleID, file, line) appears in the raw
    // (pre-dedup) diagnostic list. A header included by N TUs produces
    // N duplicate diagnostics for the same struct.
    struct DiagKey {
        std::string ruleID;
        std::string file;
        unsigned line;
        bool operator==(const DiagKey &o) const {
            return ruleID == o.ruleID && file == o.file && line == o.line;
        }
    };
    struct DiagKeyHash {
        size_t operator()(const DiagKey &k) const {
            size_t h = std::hash<std::string>{}(k.ruleID);
            h ^= std::hash<std::string>{}(k.file) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<unsigned>{}(k.line) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };

    std::unordered_map<DiagKey, unsigned, DiagKeyHash> keyCounts;
    for (const auto &d : diagnostics) {
        auto eit = d.structuralEvidence.find("thread_escape");
        if (eit == d.structuralEvidence.end()) continue;
        if (eit->second != "true" && eit->second != "yes") continue;
        keyCounts[{d.ruleID, d.location.file, d.location.line}]++;
    }

    unsigned suppressed = 0;
    for (auto &d : diagnostics) {
        if (d.suppressed) continue;

        auto eit = d.structuralEvidence.find("thread_escape");
        if (eit == d.structuralEvidence.end()) continue;
        if (eit->second != "true" && eit->second != "yes") continue;

        // Atomics present = structurally confirmed escape. Skip.
        auto ait = d.structuralEvidence.find("atomics");
        if (ait != d.structuralEvidence.end() &&
            (ait->second == "yes" || ait->second == "true"))
            continue;

        // Proven-tier findings are never suppressed.
        if (d.evidenceTier == EvidenceTier::Proven)
            continue;

        DiagKey key{d.ruleID, d.location.file, d.location.line};
        auto it = keyCounts.find(key);
        if (it != keyCounts.end() && it->second > 1)
            continue; // Multi-TU: diagnosed from multiple compilation contexts.

        // Single-TU, no atomics, not proven: suppress.
        d.suppressed = true;
        d.escalations.push_back(
            "cross-TU suppression: no multi-TU evidence of thread escape");
        ++suppressed;
    }
    return suppressed;
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

    std::sort(diagnostics.begin(), diagnostics.end(),
              [](const Diagnostic &a, const Diagnostic &b) {
                  if (a.severity != b.severity)
                      return static_cast<uint8_t>(a.severity) >
                             static_cast<uint8_t>(b.severity);
                  if (a.location.file != b.location.file)
                      return a.location.file < b.location.file;
                  if (a.location.line != b.location.line)
                      return a.location.line < b.location.line;
                  if (a.location.column != b.location.column)
                      return a.location.column < b.location.column;
                  return a.ruleID < b.ruleID;
              });
}

// --- Entry points ---

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

    sources = filterSources(sources, request.filter);
    return run(request, compDB, sources);
}

ScanResult ScanPipeline::executeWithDB(
        const ScanRequest &request,
        const clang::tooling::CompilationDatabase &compDB,
        const std::vector<std::string> &sources) {
    auto filtered = filterSources(sources, request.filter);
    return run(request, compDB, filtered);
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

    // AST analysis — parallel when multiple TUs and jobs > 1.
    unsigned jobs = request.analysisJobs;
    if (jobs == 0)
        jobs = std::max(1u, std::thread::hardware_concurrency());
    if (jobs > static_cast<unsigned>(sources.size()))
        jobs = static_cast<unsigned>(sources.size());

    int toolRet = 0;

    llvm::CrashRecoveryContext::Enable();

    if (jobs <= 1 || sources.size() <= 1) {
        // Sequential path: per-TU crash isolation.
        for (const auto &src : sources) {
            std::vector<std::string> singleTU = {src};
            std::vector<Diagnostic> tuDiags;
            LshazActionFactory factory(
                request.config, tuDiags, profileHotFuncs);

            llvm::CrashRecoveryContext CRC;
            bool crashed = !CRC.RunSafely([&]() {
                clang::tooling::ClangTool tool(compDB, singleTU);
                addResourceDirAdjuster(tool, compDB, src);
                int ret = tool.run(&factory);
                if (ret != 0) toolRet = ret;
            });

            if (crashed) {
                result.failedTUs.push_back(src);
                llvm::errs() << "lshaz: [crash] " << src
                             << " (recovered, continuing)\n";
            } else {
                auto &ff = factory.failedTUs();
                result.failedTUs.insert(result.failedTUs.end(),
                    ff.begin(), ff.end());
            }
            result.diagnostics.insert(result.diagnostics.end(),
                std::make_move_iterator(tuDiags.begin()),
                std::make_move_iterator(tuDiags.end()));
        }
    } else {
        // Parallel path: per-shard crash isolation.
        // Thread-safety:
        //   - compDB: read-only, shared safely.
        //   - request.config: const ref, read-only.
        //   - profileHotFuncs: copied by value into each factory.
        //   - shardDiags[j]: exclusive per-thread, no contention.
        //   - HotPathOracle: constructed per-TU inside LshazASTConsumer.
        std::vector<std::vector<std::string>> shards(jobs);
        for (size_t i = 0; i < sources.size(); ++i)
            shards[i % jobs].push_back(sources[i]);

        std::vector<std::vector<Diagnostic>> shardDiags(jobs);
        std::vector<std::vector<std::string>> shardFailed(jobs);
        std::vector<int> shardRet(jobs, 0);
        std::vector<std::thread> threads;
        threads.reserve(jobs);

        for (unsigned j = 0; j < jobs; ++j) {
            if (shards[j].empty()) continue;
            threads.emplace_back([&, j]() {
                // Process TUs one at a time within each thread.
                // Batching multiple TUs into a single ClangTool causes
                // failures when compile_commands.json uses relative paths
                // with different working directories per TU.
                for (const auto &src : shards[j]) {
                    std::vector<std::string> singleTU = {src};
                    std::vector<Diagnostic> tuDiags;
                    LshazActionFactory factory(
                        request.config, tuDiags, profileHotFuncs);

                    llvm::CrashRecoveryContext CRC;
                    bool ok = CRC.RunSafely([&]() {
                        clang::tooling::ClangTool tool(compDB, singleTU);
                        addResourceDirAdjuster(tool, compDB, src);
                        int ret = tool.run(&factory);
                        if (ret != 0) shardRet[j] = ret;
                    });
                    if (!ok) {
                        shardFailed[j].push_back(src);
                    } else {
                        auto &ff = factory.failedTUs();
                        shardFailed[j].insert(shardFailed[j].end(),
                            ff.begin(), ff.end());
                    }
                    shardDiags[j].insert(shardDiags[j].end(),
                        std::make_move_iterator(tuDiags.begin()),
                        std::make_move_iterator(tuDiags.end()));
                }
            });
        }

        for (auto &t : threads)
            t.join();

        // Merge results.
        for (unsigned j = 0; j < jobs; ++j) {
            if (shardRet[j] != 0) toolRet = shardRet[j];
            result.diagnostics.insert(result.diagnostics.end(),
                std::make_move_iterator(shardDiags[j].begin()),
                std::make_move_iterator(shardDiags[j].end()));
            result.failedTUs.insert(result.failedTUs.end(),
                shardFailed[j].begin(), shardFailed[j].end());
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
                  return a.functionName < b.functionName;
              });

    // IR analysis pass.
    if (request.ir.enabled && toolRet == 0) {
        report("ir", "IR emission and analysis");
        runIRPass(request, compDB, sources,
                  result.diagnostics, result.metadata);
    }

    // Cross-TU escape suppression (before dedup: needs multiplicity signal).
    if (sources.size() > 1) {
        unsigned crossTUSuppressed = applyCrossTUEscapeSuppression(
            result.diagnostics, result.totalTUsAnalyzed);
        if (crossTUSuppressed > 0)
            report("cross_tu", std::to_string(crossTUSuppressed) +
                   " finding(s) suppressed (no cross-TU escape evidence)");
    }

    // Cross-TU deduplication.
    report("dedup", "");
    deduplicateDiagnostics(result.diagnostics);

    // Interaction synthesis.
    report("interactions", "");
    synthesizeInteractions(result.diagnostics);

    // Precision budget.
    PrecisionBudget budget;
    budget.apply(result.diagnostics);

    // Calibration feedback.
    std::unique_ptr<CalibrationFeedbackStore> calStore;
    if (!request.feedback.calibrationStorePath.empty()) {
        calStore = std::make_unique<CalibrationFeedbackStore>(
            request.feedback.calibrationStorePath);
    }

    if (calStore) {
        result.suppressedByCalibration =
            applyCalibrationSuppression(request.feedback,
                                        result.diagnostics, *calStore);
    }

    // PMU trace feedback.
    if (calStore && (!request.feedback.pmuTracePath.empty() ||
                     !request.feedback.pmuPriorsPath.empty())) {
        report("pmu_feedback", "");
        applyPMUFeedback(request.feedback, result.diagnostics, *calStore);
    }

    // Filter and sort.
    filterAndSort(request.filter, result.diagnostics);

    // Summary counts.
    result.totalTUsFailed = static_cast<unsigned>(result.failedTUs.size());
    result.metadata.totalTUs = result.totalTUsAnalyzed;
    result.metadata.failedTUCount = result.totalTUsFailed;
    result.metadata.failedTUs = result.failedTUs;

    // Status.
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
