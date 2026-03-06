#include "lshaz/analysis/LshazAction.h"
#include "lshaz/core/Config.h"
#include "lshaz/core/Diagnostic.h"
#include "lshaz/core/Severity.h"
#include "lshaz/core/Version.h"
#include "lshaz/hypothesis/CalibrationFeedback.h"
#include "lshaz/hypothesis/HypothesisConstructor.h"
#include "lshaz/ir/IRAnalyzer.h"
#include "lshaz/ir/DiagnosticRefiner.h"
#include "lshaz/core/DiagnosticDedup.h"
#include "lshaz/core/DiagnosticInteraction.h"
#include "lshaz/core/PerfProfileParser.h"
#include "lshaz/hypothesis/PMUTraceFeedback.h"
#include "lshaz/core/PrecisionBudget.h"
#include "lshaz/output/OutputFormatter.h"

#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Bitcode/BitcodeReader.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/IRReader/IRReader.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/SourceMgr.h>
#include <llvm/Support/raw_ostream.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MD5.h>
#include <llvm/Support/Program.h>
#include <llvm/Support/Path.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <future>
#include <memory>
#include <mutex>
#include <semaphore>
#include <string>
#include <thread>
#include <vector>

using namespace clang::tooling;

static llvm::cl::OptionCategory LshazCat("lshaz options");

static llvm::cl::opt<std::string> ConfigPath(
    "config",
    llvm::cl::desc("Path to lshaz.config.yaml"),
    llvm::cl::value_desc("file"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> OutputFormat(
    "format",
    llvm::cl::desc("Output format (cli|json|sarif)"),
    llvm::cl::init("cli"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<bool> JSONFlag(
    "json",
    llvm::cl::desc("Emit JSON output (deprecated: use --format=json)"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> OutputFile(
    "output",
    llvm::cl::desc("Write output to file instead of stdout"),
    llvm::cl::value_desc("file"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> MinSev(
    "min-severity",
    llvm::cl::desc("Minimum severity to report (Informational|Medium|High|Critical)"),
    llvm::cl::init("Informational"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> MinEvidence(
    "min-evidence",
    llvm::cl::desc("Minimum evidence tier to report (proven|likely|speculative)"),
    llvm::cl::init("speculative"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> CalibrationStore(
    "calibration-store",
    llvm::cl::desc("Path to calibration feedback store for false-positive suppression"),
    llvm::cl::value_desc("path"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<bool> NoIR(
    "no-ir",
    llvm::cl::desc("Disable LLVM IR analysis pass (AST-only mode)"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> IROpt(
    "ir-opt",
    llvm::cl::desc("Optimization level for IR emission (O0|O1|O2). "
                    "O0 confirms structural patterns; O1+ shows optimizer effects"),
    llvm::cl::init("O0"),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<bool> NoIRCache(
    "no-ir-cache",
    llvm::cl::desc("Disable IR cache (force re-emission every run). "
                    "Recommended for CI where header changes must invalidate."),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<unsigned> IRJobs(
    "ir-jobs",
    llvm::cl::desc("Max parallel IR emission jobs (default: hardware_concurrency)"),
    llvm::cl::init(0),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<unsigned> IRBatchSize(
    "ir-batch-size",
    llvm::cl::desc("TUs per IR emission batch/shard (default: 1, i.e. per-TU). "
                    "Higher values reduce subprocess overhead for large projects."),
    llvm::cl::init(1),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> PerfProfile(
    "perf-profile",
    llvm::cl::desc("Path to perf profile data (flat or perf-script format). "
                    "Functions exceeding --hotness-threshold are treated as hot."),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<double> HotnessThreshold(
    "hotness-threshold",
    llvm::cl::desc("Minimum sample percentage to consider a function hot (default: 1.0)"),
    llvm::cl::init(1.0),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> LinkedAllocator(
    "allocator",
    llvm::cl::desc("Linked allocator library (tcmalloc|jemalloc|mimalloc). "
                    "Affects FL020 severity: thread-local cache allocators "
                    "reduce contention risk classification."),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> PMUTracePath(
    "pmu-trace",
    llvm::cl::desc("Path to production PMU trace data (JSON lines format). "
                    "Each line: {\"function\", \"file\", \"line\", \"counters\": "
                    "[{\"name\", \"value\", \"duration_ns\"}], ...}. "
                    "Used for closed-loop learning to update hazard priors."),
    llvm::cl::cat(LshazCat));

static llvm::cl::opt<std::string> PMUPriorsPath(
    "pmu-priors",
    llvm::cl::desc("Path to load/save PMU-learned hazard priors. "
                    "Priors persist across runs for incremental learning."),
    llvm::cl::cat(LshazCat));

static lshaz::Severity parseSeverity(const std::string &s) {
    if (s == "Critical")      return lshaz::Severity::Critical;
    if (s == "High")          return lshaz::Severity::High;
    if (s == "Medium")        return lshaz::Severity::Medium;
    return lshaz::Severity::Informational;
}

static lshaz::EvidenceTier parseEvidenceTier(const std::string &s) {
    if (s == "proven") return lshaz::EvidenceTier::Proven;
    if (s == "likely") return lshaz::EvidenceTier::Likely;
    return lshaz::EvidenceTier::Speculative;
}

int main(int argc, const char **argv) {
    llvm::cl::SetVersionPrinter([](llvm::raw_ostream &OS) {
        OS << lshaz::kToolName << " version " << lshaz::kToolVersion
           << " (output schema " << lshaz::kOutputSchemaVersion << ")\n";
    });

    auto parser = CommonOptionsParser::create(argc, argv, LshazCat);
    if (!parser) {
        llvm::errs() << parser.takeError();
        return 1;
    }

    // Load config.
    lshaz::Config cfg = ConfigPath.empty()
        ? lshaz::Config::defaults()
        : lshaz::Config::loadFromFile(ConfigPath);

    // CLI overrides.
    if (JSONFlag)
        cfg.jsonOutput = true;
    if (!OutputFile.empty())
        cfg.outputFile = OutputFile;
    cfg.minSeverity = parseSeverity(MinSev);
    if (!LinkedAllocator.empty())
        cfg.linkedAllocator = LinkedAllocator;

    // Build execution metadata for output provenance.
    lshaz::ExecutionMetadata execMeta;
    execMeta.toolVersion = lshaz::kToolVersion;
    execMeta.configPath = ConfigPath.getValue();
    execMeta.irOptLevel = IROpt.getValue();
    execMeta.irEnabled = !NoIR;
    execMeta.timestampEpochSec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    execMeta.sourceFiles.assign(parser->getSourcePathList().begin(),
                                parser->getSourcePathList().end());

    // --- Profile-guided hotness ---
    std::unordered_set<std::string> profileHotFuncs;
    std::string profilePath = PerfProfile.getValue();
    if (profilePath.empty())
        profilePath = cfg.perfProfilePath;
    if (!profilePath.empty()) {
        lshaz::PerfProfileParser profParser;
        if (profParser.parse(profilePath)) {
            double threshold = HotnessThreshold.getValue();
            if (cfg.hotnessThresholdPct > 0 && threshold == 1.0)
                threshold = cfg.hotnessThresholdPct;
            profileHotFuncs = profParser.hotFunctions(threshold);
            llvm::errs() << "lshaz: loaded " << profParser.totalSamples()
                         << " samples, " << profileHotFuncs.size()
                         << " hot function(s) at >=" << threshold << "%\n";
        } else {
            llvm::errs() << "lshaz: warning: failed to parse profile '"
                         << profilePath << "'\n";
        }
    }

    // Run analysis.
    ClangTool tool(parser->getCompilations(), parser->getSourcePathList());

    std::vector<lshaz::Diagnostic> diagnostics;
    lshaz::LshazActionFactory factory(
        cfg, diagnostics, std::move(profileHotFuncs));

    int ret = tool.run(&factory);

    // --- IR analysis pass ---
    // Emit LLVM IR via structured subprocess, then parse with IRReader.
    if (!NoIR && ret == 0) {
        lshaz::IRAnalyzer irAnalyzer;
        std::string optLevel = "-" + IROpt.getValue();

        struct IRJob {
            std::string srcPath;
            std::string compilerPath;  // resolved absolute path
            std::vector<std::string> argv;
            std::string irFile;
            std::string errFile;
            bool cached = false;       // true if IR file already exists
        };
        std::vector<IRJob> jobs;

        for (const auto &srcPath : parser->getSourcePathList()) {
            auto cmds = parser->getCompilations()
                            .getCompileCommands(srcPath);
            if (cmds.empty())
                continue;

            // Extract compiler from compile_commands.json argv[0].
            // Fixed compilation databases (-- syntax) set argv[0] to the tool
            // binary path, not a real compiler. Validate the resolved path is
            // an actual executable before using it.
            const std::string &dbCompiler = cmds.front().CommandLine.front();
            std::string compilerPath;
            auto resolvedOrErr = llvm::sys::findProgramByName(dbCompiler);
            if (resolvedOrErr &&
                llvm::sys::fs::can_execute(*resolvedOrErr)) {
                compilerPath = *resolvedOrErr;
            }
            if (compilerPath.empty()) {
                // Fallback: find a usable clang++ on PATH.
                for (const char *fallback : {"clang++", "clang++-18",
                                              "clang++-17", "clang++-16"}) {
                    auto fb = llvm::sys::findProgramByName(fallback);
                    if (fb && llvm::sys::fs::can_execute(*fb)) {
                        compilerPath = *fb;
                        break;
                    }
                }
            }
            if (compilerPath.empty()) {
                llvm::errs() << "lshaz: warning: cannot resolve compiler '"
                             << dbCompiler << "', skipping IR for "
                             << srcPath << "\n";
                continue;
            }

            // Build structured argv: compiler -S -emit-llvm -g -O<level>
            //   + all original flags (skip argv[0], -c, -o <file>, source)
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

            // Cache key: MD5(source content + mtime + compile args + tool version
            //                 + dependency file contents if available).
            // Header dependency gap: without a full -M dep scan, header changes
            // may not invalidate cache. Use --no-ir-cache in CI for correctness.
            llvm::MD5 hasher;
            auto srcBuf = llvm::MemoryBuffer::getFile(srcPath);
            if (srcBuf)
                hasher.update((*srcBuf)->getBuffer());
            else
                hasher.update(srcPath);

            // Include source mtime to detect filesystem-level changes.
            llvm::sys::fs::file_status srcStat;
            if (!llvm::sys::fs::status(srcPath, srcStat)) {
                auto mtime = srcStat.getLastModificationTime()
                                 .time_since_epoch().count();
                hasher.update(llvm::StringRef(
                    reinterpret_cast<const char *>(&mtime), sizeof(mtime)));
            }

            // Hash dependency file (.d) if present alongside source.
            // Build systems often produce these; their content lists all
            // included headers, so hashing the dep file transitively
            // captures header changes.
            llvm::SmallString<256> depPath(srcPath);
            llvm::sys::path::replace_extension(depPath, ".d");
            auto depBuf = llvm::MemoryBuffer::getFile(depPath);
            if (depBuf)
                hasher.update((*depBuf)->getBuffer());

            for (const auto &a : argv)
                hasher.update(a);
            hasher.update(lshaz::kToolVersion);
            llvm::MD5::MD5Result hashResult;
            hasher.final(hashResult);
            llvm::SmallString<32> hashStr;
            llvm::MD5::stringifyResult(hashResult, hashStr);

            llvm::SmallString<128> tmpDir;
            llvm::sys::path::system_temp_directory(/*erasedOnReboot=*/true, tmpDir);
            llvm::SmallString<128> irPath(tmpDir), errPath(tmpDir);
            llvm::sys::path::append(irPath,
                "lshaz-" + std::string(hashStr) + ".ll");
            llvm::sys::path::append(errPath,
                "lshaz-" + std::string(hashStr) + ".err");

            // Incremental cache: reuse existing IR if hash matches.
            bool cached = !NoIRCache && llvm::sys::fs::exists(irPath);

            argv.push_back("-o");
            argv.push_back(std::string(irPath));
            argv.push_back(srcPath);

            jobs.push_back({srcPath, compilerPath, std::move(argv),
                            std::string(irPath), std::string(errPath), cached});

            // Track unique compilers for provenance.
            bool seen = false;
            for (const auto &ci : execMeta.compilers)
                if (ci.path == compilerPath) { seen = true; break; }
            if (!seen)
                execMeta.compilers.push_back({compilerPath, {}});
        }

        if (jobs.empty() && !parser->getSourcePathList().empty()) {
            llvm::errs() << "lshaz: warning: no compilable IR jobs, "
                         << "skipping IR analysis pass\n";
        }

        // --- Shard-based parallel IR emission and analysis ---
        //
        // Jobs are grouped into shards of --ir-batch-size TUs. Each shard:
        //   1. Emits IR for its TUs (subprocess per TU, bounded by semaphore)
        //   2. Parses IR into a shard-local LLVMContext + IRAnalyzer
        //   3. Returns the shard IRAnalyzer for merge
        //
        // Shards run in parallel bounded by --ir-jobs. Each shard owns its
        // LLVMContext, eliminating the single-context bottleneck.
        unsigned maxWorkers = IRJobs.getValue();
        if (maxWorkers == 0)
            maxWorkers = std::max(1u, std::thread::hardware_concurrency());
        unsigned batchSize = std::max(1u, IRBatchSize.getValue());

        // Build shards: vector of job index ranges.
        struct Shard {
            size_t begin;
            size_t end; // exclusive
        };
        std::vector<Shard> shards;
        for (size_t i = 0; i < jobs.size(); i += batchSize)
            shards.push_back({i, std::min(i + batchSize, jobs.size())});

        unsigned shardWorkers = std::min(maxWorkers,
                                          static_cast<unsigned>(shards.size()));
        std::counting_semaphore<> sem(shardWorkers);

        struct IRResult {
            int exitCode = -1;
            std::string errMsg;
        };

        // Emit a single job synchronously. Returns exit code.
        auto emitOne = [](const IRJob &job) -> IRResult {
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
        };

        struct ShardResult {
            lshaz::IRAnalyzer analyzer;
            std::vector<std::pair<size_t, IRResult>> jobResults;
        };

        std::vector<std::future<ShardResult>> shardFutures;
        shardFutures.reserve(shards.size());

        for (const auto &shard : shards) {
            shardFutures.push_back(std::async(std::launch::async,
                [&sem, &jobs, &emitOne](size_t begin, size_t end) -> ShardResult {
                    sem.acquire();

                    ShardResult sr;

                    // Phase 1: emit IR for all TUs in this shard.
                    for (size_t i = begin; i < end; ++i)
                        sr.jobResults.push_back({i, emitOne(jobs[i])});

                    // Phase 2: parse and analyze in shard-local context.
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

        // Collect shard results and merge into main analyzer.
        for (auto &future : shardFutures) {
            auto sr = future.get();

            // Log failures.
            for (const auto &[idx, result] : sr.jobResults) {
                if (result.exitCode != 0) {
                    auto errBuf = llvm::MemoryBuffer::getFile(jobs[idx].errFile);
                    if (errBuf && !(*errBuf)->getBuffer().empty()) {
                        llvm::errs() << "lshaz: IR emission failed for "
                                     << jobs[idx].srcPath << ":\n"
                                     << (*errBuf)->getBuffer() << "\n";
                    } else if (!result.errMsg.empty()) {
                        llvm::errs() << "lshaz: IR emission failed for "
                                     << jobs[idx].srcPath << ": "
                                     << result.errMsg << "\n";
                    }
                }

                // Cleanup: retain cached IR, remove err files and failed IR.
                if (!jobs[idx].cached && result.exitCode != 0)
                    llvm::sys::fs::remove(jobs[idx].irFile);
                llvm::sys::fs::remove(jobs[idx].errFile);
            }

            // Shard-level reduction: merge profiles into main analyzer.
            irAnalyzer.mergeFrom(std::move(sr.analyzer));
        }

        if (!irAnalyzer.profiles().empty()) {
            lshaz::DiagnosticRefiner refiner(irAnalyzer.profiles());
            refiner.refine(diagnostics);
        }
    }

    // --- Cross-TU deduplication ---
    // Struct-level rules emit identical diagnostics when the same header
    // is included by multiple TUs. Merge duplicates, keep highest confidence.
    lshaz::deduplicateDiagnostics(diagnostics);

    // --- Hazard interaction synthesis ---
    // Correlate diagnostics from different rules at the same site.
    // Synthesize compound hazard diagnostics (FL091) with site-specific
    // evidence drawn from the InteractionEligibilityMatrix.
    lshaz::synthesizeInteractions(diagnostics);

    // --- Precision budget governance ---
    // Per-rule confidence floors, severity caps, and emission limits.
    lshaz::PrecisionBudget precisionBudget;
    precisionBudget.apply(diagnostics);

    // --- Calibration-based false-positive suppression ---
    std::unique_ptr<lshaz::CalibrationFeedbackStore> calStore;
    if (!CalibrationStore.empty()) {
        calStore = std::make_unique<lshaz::CalibrationFeedbackStore>(
            CalibrationStore);
    }

    unsigned suppressed = 0;
    if (calStore) {
        diagnostics.erase(
            std::remove_if(diagnostics.begin(), diagnostics.end(),
                           [&](const lshaz::Diagnostic &d) {
                               auto hc = lshaz::HypothesisConstructor
                                   ::mapRuleToHazardClass(d.ruleID);
                               auto features = lshaz::HypothesisConstructor
                                   ::extractFeatures(d);
                               // Safety rail: never suppress high-severity
                               // proven findings via calibration.
                               bool highSev =
                                   d.severity == lshaz::Severity::Critical ||
                                   d.severity == lshaz::Severity::High;
                               bool proven =
                                   d.evidenceTier == lshaz::EvidenceTier::Proven;
                               if (highSev && proven)
                                   return false;

                               if (calStore->isKnownFalsePositive(features, hc)) {
                                   ++suppressed;
                                   return true;
                               }
                               return false;
                           }),
            diagnostics.end());

        if (suppressed > 0) {
            llvm::errs() << "lshaz: suppressed " << suppressed
                         << " diagnostic(s) via calibration feedback\n";
        }
    }

    // --- Closed-loop PMU trace feedback ---
    // Ingest production PMU traces to update hazard priors and adjust
    // diagnostic confidence based on observed true/false positive rates.
    if (calStore && (!PMUTracePath.empty() || !PMUPriorsPath.empty())) {
        lshaz::PMUTraceFeedbackLoop feedbackLoop(*calStore);

        // Load persisted priors from previous runs.
        if (!PMUPriorsPath.empty())
            feedbackLoop.loadPriors(PMUPriorsPath);

        // Parse and ingest PMU trace file (JSON-lines: one record per line).
        // Format: function<TAB>file<TAB>line<TAB>counter_name<TAB>value<TAB>duration_ns
        // Multiple counter lines per function are accumulated.
        if (!PMUTracePath.empty()) {
            auto traceBuf = llvm::MemoryBuffer::getFile(PMUTracePath.getValue());
            if (traceBuf) {
                llvm::StringRef data = (*traceBuf)->getBuffer();
                llvm::SmallVector<llvm::StringRef, 0> lines;
                data.split(lines, '\n', /*MaxSplit=*/-1, /*KeepEmpty=*/false);

                lshaz::PMUTraceRecord currentRecord;
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

                    // If new function/location, ingest previous record.
                    if (!currentRecord.functionName.empty() &&
                        (currentRecord.functionName != func ||
                         currentRecord.sourceLine != srcLine)) {
                        // Correlate to diagnostics.
                        for (const auto &d : diagnostics) {
                            if (d.functionName == currentRecord.functionName ||
                                (d.location.file == currentRecord.sourceFile &&
                                 d.location.line == currentRecord.sourceLine)) {
                                auto hc = lshaz::HypothesisConstructor
                                    ::mapRuleToHazardClass(d.ruleID);
                                auto features = lshaz::HypothesisConstructor
                                    ::extractFeatures(d);
                                feedbackLoop.ingestTrace(
                                    currentRecord, hc, features);
                                break;
                            }
                        }
                        currentRecord = {};
                    }

                    currentRecord.functionName = func;
                    currentRecord.sourceFile = file;
                    currentRecord.sourceLine = srcLine;

                    lshaz::PMUSample sample;
                    sample.counterName = fields[3].str();
                    fields[4].getAsInteger(10, sample.value);
                    if (fields.size() > 5)
                        fields[5].getAsInteger(10, sample.duration_ns);
                    currentRecord.samples.push_back(std::move(sample));
                }

                // Flush last record.
                if (!currentRecord.functionName.empty()) {
                    for (const auto &d : diagnostics) {
                        if (d.functionName == currentRecord.functionName ||
                            (d.location.file == currentRecord.sourceFile &&
                             d.location.line == currentRecord.sourceLine)) {
                            auto hc = lshaz::HypothesisConstructor
                                ::mapRuleToHazardClass(d.ruleID);
                            auto features = lshaz::HypothesisConstructor
                                ::extractFeatures(d);
                            feedbackLoop.ingestTrace(
                                currentRecord, hc, features);
                            break;
                        }
                    }
                }
            } else {
                llvm::errs() << "lshaz: warning: cannot read PMU trace '"
                             << PMUTracePath.getValue() << "'\n";
            }
        }

        // Apply learned priors to adjust diagnostic confidence.
        for (auto &d : diagnostics) {
            auto hc = lshaz::HypothesisConstructor
                ::mapRuleToHazardClass(d.ruleID);
            d.confidence = feedbackLoop.adjustConfidence(d.confidence, hc);
        }

        // Save updated priors for next run.
        if (!PMUPriorsPath.empty())
            feedbackLoop.savePriors(PMUPriorsPath);
    }

    // Filter suppressed, minimum severity, and evidence tier.
    auto minTier = parseEvidenceTier(MinEvidence);
    diagnostics.erase(
        std::remove_if(diagnostics.begin(), diagnostics.end(),
                       [&](const lshaz::Diagnostic &d) {
                           if (d.suppressed)
                               return true;
                           if (static_cast<uint8_t>(d.severity) <
                               static_cast<uint8_t>(cfg.minSeverity))
                               return true;
                           if (static_cast<uint8_t>(d.evidenceTier) >
                               static_cast<uint8_t>(minTier))
                               return true;
                           return false;
                       }),
        diagnostics.end());

    // Sort: Critical first, then by file/line.
    std::sort(diagnostics.begin(), diagnostics.end(),
              [](const lshaz::Diagnostic &a, const lshaz::Diagnostic &b) {
                  if (a.severity != b.severity)
                      return static_cast<uint8_t>(a.severity) >
                             static_cast<uint8_t>(b.severity);
                  if (a.location.file != b.location.file)
                      return a.location.file < b.location.file;
                  return a.location.line < b.location.line;
              });

    // Format output.
    std::string fmt = OutputFormat.getValue();
    if (JSONFlag && fmt == "cli")
        fmt = "json"; // backward compat

    std::unique_ptr<lshaz::OutputFormatter> formatter;
    if (fmt == "sarif")
        formatter = std::make_unique<lshaz::SARIFOutputFormatter>();
    else if (fmt == "json" || cfg.jsonOutput)
        formatter = std::make_unique<lshaz::JSONOutputFormatter>();
    else {
        if (fmt != "cli")
            llvm::errs() << "lshaz: warning: unknown format '" << fmt
                         << "', defaulting to cli\n";
        formatter = std::make_unique<lshaz::CLIOutputFormatter>();
    }

    std::string output = formatter->format(diagnostics, execMeta);

    // Emit.
    if (cfg.outputFile.empty()) {
        llvm::outs() << output;
    } else {
        std::error_code EC;
        llvm::raw_fd_ostream file(cfg.outputFile, EC, llvm::sys::fs::OF_Text);
        if (EC) {
            llvm::errs() << "lshaz: error: cannot open output file '"
                         << cfg.outputFile << "': " << EC.message() << "\n";
            return 3;
        }
        file << output;
    }

    // Exit codes:
    //   0 = clean (no diagnostics, no errors)
    //   1 = diagnostics found (analysis succeeded, findings emitted)
    //   2 = parse/compilation error (ClangTool failed, no findings)
    //   3 = tool infrastructure failure (output file, config, etc.)
    bool parseError = (ret != 0);
    bool hasFindings = !diagnostics.empty();

    if (parseError && hasFindings) {
        llvm::errs() << "lshaz: warning: ClangTool returned non-zero ("
                     << ret << "), some sources may have parse errors; "
                     << diagnostics.size() << " finding(s) from successful parses\n";
        return 1;
    }
    if (parseError) {
        llvm::errs() << "lshaz: error: ClangTool returned non-zero ("
                     << ret << "), input has parse/compilation errors\n";
        return 2;
    }
    return hasFindings ? 1 : 0;
}
