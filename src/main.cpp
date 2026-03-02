#include "faultline/analysis/FaultlineAction.h"
#include "faultline/core/Config.h"
#include "faultline/core/Diagnostic.h"
#include "faultline/core/Severity.h"
#include "faultline/core/Version.h"
#include "faultline/hypothesis/CalibrationFeedback.h"
#include "faultline/hypothesis/HypothesisConstructor.h"
#include "faultline/ir/IRAnalyzer.h"
#include "faultline/ir/DiagnosticRefiner.h"
#include "faultline/output/OutputFormatter.h"

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

static llvm::cl::OptionCategory FaultlineCat("faultline options");

static llvm::cl::opt<std::string> ConfigPath(
    "config",
    llvm::cl::desc("Path to faultline.config.yaml"),
    llvm::cl::value_desc("file"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<std::string> OutputFormat(
    "format",
    llvm::cl::desc("Output format (cli|json|sarif)"),
    llvm::cl::init("cli"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<bool> JSONFlag(
    "json",
    llvm::cl::desc("Emit JSON output (deprecated: use --format=json)"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<std::string> OutputFile(
    "output",
    llvm::cl::desc("Write output to file instead of stdout"),
    llvm::cl::value_desc("file"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<std::string> MinSev(
    "min-severity",
    llvm::cl::desc("Minimum severity to report (Informational|Medium|High|Critical)"),
    llvm::cl::init("Informational"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<std::string> MinEvidence(
    "min-evidence",
    llvm::cl::desc("Minimum evidence tier to report (proven|likely|speculative)"),
    llvm::cl::init("speculative"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<std::string> CalibrationStore(
    "calibration-store",
    llvm::cl::desc("Path to calibration feedback store for false-positive suppression"),
    llvm::cl::value_desc("path"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<bool> NoIR(
    "no-ir",
    llvm::cl::desc("Disable LLVM IR analysis pass (AST-only mode)"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<std::string> IROpt(
    "ir-opt",
    llvm::cl::desc("Optimization level for IR emission (O0|O1|O2). "
                    "O0 confirms structural patterns; O1+ shows optimizer effects"),
    llvm::cl::init("O0"),
    llvm::cl::cat(FaultlineCat));

static llvm::cl::opt<bool> NoIRCache(
    "no-ir-cache",
    llvm::cl::desc("Disable IR cache (force re-emission every run). "
                    "Recommended for CI where header changes must invalidate."),
    llvm::cl::cat(FaultlineCat));

static faultline::Severity parseSeverity(const std::string &s) {
    if (s == "Critical")      return faultline::Severity::Critical;
    if (s == "High")          return faultline::Severity::High;
    if (s == "Medium")        return faultline::Severity::Medium;
    return faultline::Severity::Informational;
}

static faultline::EvidenceTier parseEvidenceTier(const std::string &s) {
    if (s == "proven") return faultline::EvidenceTier::Proven;
    if (s == "likely") return faultline::EvidenceTier::Likely;
    return faultline::EvidenceTier::Speculative;
}

int main(int argc, const char **argv) {
    auto parser = CommonOptionsParser::create(argc, argv, FaultlineCat);
    if (!parser) {
        llvm::errs() << parser.takeError();
        return 1;
    }

    // Load config.
    faultline::Config cfg = ConfigPath.empty()
        ? faultline::Config::defaults()
        : faultline::Config::loadFromFile(ConfigPath);

    // CLI overrides.
    if (JSONFlag)
        cfg.jsonOutput = true;
    if (!OutputFile.empty())
        cfg.outputFile = OutputFile;
    cfg.minSeverity = parseSeverity(MinSev);

    // Build execution metadata for output provenance.
    faultline::ExecutionMetadata execMeta;
    execMeta.toolVersion = faultline::kToolVersion;
    execMeta.configPath = ConfigPath.getValue();
    execMeta.irOptLevel = IROpt.getValue();
    execMeta.irEnabled = !NoIR;
    execMeta.timestampEpochSec = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count());
    execMeta.sourceFiles.assign(parser->getSourcePathList().begin(),
                                parser->getSourcePathList().end());

    // Run analysis.
    ClangTool tool(parser->getCompilations(), parser->getSourcePathList());

    std::vector<faultline::Diagnostic> diagnostics;
    faultline::FaultlineActionFactory factory(cfg, diagnostics);

    int ret = tool.run(&factory);

    // --- IR analysis pass ---
    // Emit LLVM IR via structured subprocess, then parse with IRReader.
    if (!NoIR && ret == 0) {
        faultline::IRAnalyzer irAnalyzer;
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
                llvm::errs() << "faultline: warning: cannot resolve compiler '"
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
            hasher.update(faultline::kToolVersion);
            llvm::MD5::MD5Result hashResult;
            hasher.final(hashResult);
            llvm::SmallString<32> hashStr;
            llvm::MD5::stringifyResult(hashResult, hashStr);

            llvm::SmallString<128> tmpDir;
            llvm::sys::path::system_temp_directory(/*erasedOnReboot=*/true, tmpDir);
            llvm::SmallString<128> irPath(tmpDir), errPath(tmpDir);
            llvm::sys::path::append(irPath,
                "faultline-" + std::string(hashStr) + ".ll");
            llvm::sys::path::append(errPath,
                "faultline-" + std::string(hashStr) + ".err");

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
            llvm::errs() << "faultline: warning: no compilable IR jobs, "
                         << "skipping IR analysis pass\n";
        }

        // Bounded parallel IR emission.
        unsigned maxWorkers = std::max(1u, std::thread::hardware_concurrency());
        maxWorkers = std::min(maxWorkers, static_cast<unsigned>(jobs.size()));
        std::counting_semaphore<> sem(maxWorkers);

        struct IRResult {
            int exitCode = -1;
            std::string errMsg;
        };
        std::vector<std::future<IRResult>> futures;
        futures.reserve(jobs.size());

        for (const auto &job : jobs) {
            if (job.cached) {
                // Cache hit: no compilation needed.
                std::promise<IRResult> p;
                p.set_value({0, {}});
                futures.push_back(p.get_future());
                continue;
            }

            futures.push_back(std::async(std::launch::async,
                [&sem](const std::string &program,
                       const std::vector<std::string> &argvOwned,
                       const std::string &errFile) -> IRResult {
                    sem.acquire();

                    std::vector<llvm::StringRef> argRefs;
                    argRefs.reserve(argvOwned.size());
                    for (const auto &a : argvOwned)
                        argRefs.push_back(a);

                    // Redirect: stdin=none, stdout=none, stderr=errFile.
                    llvm::StringRef errRedirect(errFile);
                    std::optional<llvm::StringRef> redirects[] = {
                        std::nullopt,   // stdin
                        std::nullopt,   // stdout
                        errRedirect     // stderr
                    };

                    IRResult result;
                    bool failed = false;
                    result.exitCode = llvm::sys::ExecuteAndWait(
                        program, argRefs,
                        /*Env=*/std::nullopt, redirects,
                        /*SecondsToWait=*/120, /*MemoryLimit=*/0,
                        &result.errMsg, &failed);
                    if (failed)
                        result.exitCode = -1;

                    sem.release();
                    return result;
                },
                job.compilerPath, job.argv, job.errFile));
        }

        // Collect results and parse IR sequentially (LLVMContext is not thread-safe).
        llvm::LLVMContext llvmCtx;
        for (size_t i = 0; i < jobs.size(); ++i) {
            auto result = futures[i].get();

            if (result.exitCode != 0) {
                // Log compiler failure with captured stderr.
                auto errBuf = llvm::MemoryBuffer::getFile(jobs[i].errFile);
                if (errBuf && !(*errBuf)->getBuffer().empty()) {
                    llvm::errs() << "faultline: IR emission failed for "
                                 << jobs[i].srcPath << ":\n"
                                 << (*errBuf)->getBuffer() << "\n";
                } else if (!result.errMsg.empty()) {
                    llvm::errs() << "faultline: IR emission failed for "
                                 << jobs[i].srcPath << ": "
                                 << result.errMsg << "\n";
                }
            } else {
                llvm::SMDiagnostic parseErr;
                auto mod = llvm::parseIRFile(jobs[i].irFile, parseErr, llvmCtx);
                if (mod)
                    irAnalyzer.analyzeModule(*mod);
            }

            // Cached IR files are retained for future runs.
            // Only clean up err files and failed non-cached IR.
            if (!jobs[i].cached && result.exitCode != 0)
                llvm::sys::fs::remove(jobs[i].irFile);
            llvm::sys::fs::remove(jobs[i].errFile);
        }

        if (!irAnalyzer.profiles().empty()) {
            faultline::DiagnosticRefiner refiner(irAnalyzer.profiles());
            refiner.refine(diagnostics);
        }
    }

    // --- Calibration-based false-positive suppression ---
    std::unique_ptr<faultline::CalibrationFeedbackStore> calStore;
    if (!CalibrationStore.empty()) {
        calStore = std::make_unique<faultline::CalibrationFeedbackStore>(
            CalibrationStore);
    }

    unsigned suppressed = 0;
    if (calStore) {
        diagnostics.erase(
            std::remove_if(diagnostics.begin(), diagnostics.end(),
                           [&](const faultline::Diagnostic &d) {
                               auto hc = faultline::HypothesisConstructor
                                   ::mapRuleToHazardClass(d.ruleID);
                               auto features = faultline::HypothesisConstructor
                                   ::extractFeatures(d);
                               // Safety rail: never suppress high-severity
                               // proven findings via calibration.
                               bool highSev =
                                   d.severity == faultline::Severity::Critical ||
                                   d.severity == faultline::Severity::High;
                               bool proven =
                                   d.evidenceTier == faultline::EvidenceTier::Proven;
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
            llvm::errs() << "faultline: suppressed " << suppressed
                         << " diagnostic(s) via calibration feedback\n";
        }
    }

    // Filter suppressed, minimum severity, and evidence tier.
    auto minTier = parseEvidenceTier(MinEvidence);
    diagnostics.erase(
        std::remove_if(diagnostics.begin(), diagnostics.end(),
                       [&](const faultline::Diagnostic &d) {
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
              [](const faultline::Diagnostic &a, const faultline::Diagnostic &b) {
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

    std::unique_ptr<faultline::OutputFormatter> formatter;
    if (fmt == "sarif")
        formatter = std::make_unique<faultline::SARIFOutputFormatter>();
    else if (fmt == "json" || cfg.jsonOutput)
        formatter = std::make_unique<faultline::JSONOutputFormatter>();
    else
        formatter = std::make_unique<faultline::CLIOutputFormatter>();

    std::string output = formatter->format(diagnostics, execMeta);

    // Emit.
    if (cfg.outputFile.empty()) {
        llvm::outs() << output;
    } else {
        std::error_code EC;
        llvm::raw_fd_ostream file(cfg.outputFile, EC, llvm::sys::fs::OF_Text);
        if (EC) {
            llvm::errs() << "faultline: error: cannot open output file '"
                         << cfg.outputFile << "': " << EC.message() << "\n";
            return 1;
        }
        file << output;
    }

    // Exit codes:
    //   0 = clean (no diagnostics)
    //   1 = diagnostics found
    //   2 = parse error (ClangTool failed to process input)
    if (ret != 0) {
        llvm::errs() << "faultline: warning: ClangTool returned non-zero ("
                     << ret << "), input may have parse errors\n";
    }
    return diagnostics.empty() ? (ret == 0 ? 0 : 2) : 1;
}
