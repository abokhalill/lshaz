#include "ScanCommand.h"

#include "lshaz/core/Config.h"
#include "lshaz/core/Version.h"
#include "lshaz/output/OutputFormatter.h"
#include "lshaz/pipeline/RepoProvider.h"
#include "lshaz/pipeline/ScanPipeline.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>

#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#include <unordered_map>

namespace lshaz {

namespace {

struct ScanArgs {
    std::string target;           // path or URL
    std::string compileDBPath;
    std::string configPath;
    std::string format = "cli";
    std::string outputFile;
    std::string minSeverity = "Informational";
    std::string minEvidence = "speculative";
    std::string irOpt = "O0";
    std::string perfProfile;
    std::string allocator;
    std::string calibrationStore;
    std::string pmuTrace;
    std::string pmuPriors;
    double hotnessThreshold = 1.0;
    unsigned irJobs = 0;
    unsigned irBatchSize = 1;
    unsigned maxFiles = 0;
    unsigned jobs = 0;
    std::vector<std::string> includeFiles;
    std::vector<std::string> excludeFiles;
    bool noIR = false;
    bool noIRCache = false;
    bool watch = false;
    unsigned watchInterval = 2;
    bool help = false;
};

void printScanUsage() {
    llvm::errs()
        << "Usage: lshaz scan <path> [options]\n"
        << "\n"
        << "Analyze a C/C++ project for hardware-level performance hazards.\n"
        << "\n"
        << "Arguments:\n"
        << "  <path>                   Project root directory (or compile_commands.json path)\n"
        << "\n"
        << "Options:\n"
        << "  --compile-db <path>      Explicit path to compile_commands.json\n"
        << "  --config <path>          Path to lshaz.config.yaml\n"
        << "  --format <cli|json|sarif> Output format (default: cli)\n"
        << "  --output <path>          Write output to file instead of stdout\n"
        << "  --min-severity <level>   Minimum severity (Informational|Medium|High|Critical)\n"
        << "  --min-evidence <tier>    Minimum evidence tier (proven|likely|speculative)\n"
        << "  --no-ir                  Disable LLVM IR analysis pass\n"
        << "  --ir-opt <O0|O1|O2>     IR optimization level (default: O0)\n"
        << "  --ir-jobs <N>            Max parallel IR jobs (default: hardware_concurrency)\n"
        << "  --jobs <N>               Parallel AST analysis threads (default: hardware_concurrency)\n"
        << "  --max-files <N>          Maximum translation units to analyze\n"
        << "  --include <pattern>      Only analyze files matching pattern (repeatable)\n"
        << "  --exclude <pattern>      Skip files matching pattern (repeatable)\n"
        << "  --perf-profile <path>    Path to perf profile for hotness guidance\n"
        << "  --allocator <name>       Linked allocator (tcmalloc|jemalloc|mimalloc)\n"
        << "  --watch                  Watch mode: re-scan on file changes\n"
        << "  --watch-interval <N>     Seconds between polls (default: 2)\n"
        << "  --help                   Show this help\n";
}

bool consumeArg(int &i, int argc, const char **argv, const char *flag,
                std::string &out) {
    if (std::strcmp(argv[i], flag) == 0 && i + 1 < argc) {
        out = argv[++i];
        return true;
    }
    return false;
}

bool consumeArgUnsigned(int &i, int argc, const char **argv, const char *flag,
                        unsigned &out) {
    std::string s;
    if (consumeArg(i, argc, argv, flag, s)) {
        out = static_cast<unsigned>(std::stoul(s));
        return true;
    }
    return false;
}

bool parseScanArgs(int argc, const char **argv, ScanArgs &args) {
    for (int i = 0; i < argc; ++i) {
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            args.help = true;
            return true;
        }
        if (consumeArg(i, argc, argv, "--compile-db", args.compileDBPath)) continue;
        if (consumeArg(i, argc, argv, "--config", args.configPath)) continue;
        if (consumeArg(i, argc, argv, "--format", args.format)) continue;
        if (consumeArg(i, argc, argv, "--output", args.outputFile)) continue;
        if (consumeArg(i, argc, argv, "--min-severity", args.minSeverity)) continue;
        if (consumeArg(i, argc, argv, "--min-evidence", args.minEvidence)) continue;
        if (consumeArg(i, argc, argv, "--ir-opt", args.irOpt)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--ir-jobs", args.irJobs)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--ir-batch-size", args.irBatchSize)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--jobs", args.jobs)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--max-files", args.maxFiles)) continue;
        { std::string v; if (consumeArg(i, argc, argv, "--include", v)) { args.includeFiles.push_back(v); continue; } }
        { std::string v; if (consumeArg(i, argc, argv, "--exclude", v)) { args.excludeFiles.push_back(v); continue; } }
        if (consumeArg(i, argc, argv, "--perf-profile", args.perfProfile)) continue;
        if (consumeArg(i, argc, argv, "--allocator", args.allocator)) continue;
        if (consumeArg(i, argc, argv, "--calibration-store", args.calibrationStore)) continue;
        if (consumeArg(i, argc, argv, "--pmu-trace", args.pmuTrace)) continue;
        if (consumeArg(i, argc, argv, "--pmu-priors", args.pmuPriors)) continue;
        if (std::strcmp(argv[i], "--no-ir") == 0) { args.noIR = true; continue; }
        if (std::strcmp(argv[i], "--no-ir-cache") == 0) { args.noIRCache = true; continue; }
        if (std::strcmp(argv[i], "--watch") == 0) { args.watch = true; continue; }
        if (consumeArgUnsigned(i, argc, argv, "--watch-interval", args.watchInterval)) continue;

        if (argv[i][0] == '-') {
            llvm::errs() << "lshaz scan: unknown option '" << argv[i] << "'\n";
            return false;
        }

        if (args.target.empty()) {
            args.target = argv[i];
        } else {
            llvm::errs() << "lshaz scan: unexpected argument '" << argv[i] << "'\n";
            return false;
        }
    }
    return true;
}

Severity parseSeverity(const std::string &s) {
    if (s == "Critical") return Severity::Critical;
    if (s == "High")     return Severity::High;
    if (s == "Medium")   return Severity::Medium;
    return Severity::Informational;
}

EvidenceTier parseEvidenceTier(const std::string &s) {
    if (s == "proven") return EvidenceTier::Proven;
    if (s == "likely") return EvidenceTier::Likely;
    return EvidenceTier::Speculative;
}

int emitOutput(const ScanResult &result, const ScanRequest &request,
               const std::string &format, const std::string &outputFile) {
    std::unique_ptr<OutputFormatter> formatter;
    if (format == "sarif")
        formatter = std::make_unique<SARIFOutputFormatter>();
    else if (format == "json")
        formatter = std::make_unique<JSONOutputFormatter>();
    else
        formatter = std::make_unique<CLIOutputFormatter>();

    std::string output = formatter->format(result.diagnostics, result.metadata);

    if (outputFile.empty()) {
        llvm::outs() << output;
    } else {
        std::error_code EC;
        llvm::raw_fd_ostream file(outputFile, EC, llvm::sys::fs::OF_Text);
        if (EC) {
            llvm::errs() << "lshaz: error: cannot open output file '"
                         << outputFile << "': " << EC.message() << "\n";
            return 3;
        }
        file << output;
    }
    return static_cast<int>(result.status);
}

} // anonymous namespace

int runScanCommand(int argc, const char **argv) {
    ScanArgs args;
    if (!parseScanArgs(argc, argv, args)) {
        printScanUsage();
        return 3;
    }
    if (args.help) {
        printScanUsage();
        return 0;
    }
    if (args.target.empty()) {
        llvm::errs() << "lshaz scan: missing target path\n\n";
        printScanUsage();
        return 3;
    }

    // Resolve target: URL -> clone, .json -> compile DB, directory -> project root.
    std::string target = args.target;
    bool isCompileDB = false;
    RepoAcquisition repoAcq;

    if (RepoProvider::isRemoteURL(target)) {
        llvm::errs() << "lshaz: cloning " << target << "...\n";
        repoAcq = RepoProvider::acquire(target);
        if (!repoAcq.error.empty()) {
            llvm::errs() << "lshaz scan: " << repoAcq.error << "\n";
            RepoProvider::cleanup(repoAcq);
            return 3;
        }
        target = repoAcq.localPath;
        llvm::errs() << "lshaz: cloned to " << target << "\n";
    } else if (llvm::sys::path::extension(target) == ".json") {
        isCompileDB = true;
    } else if (!llvm::sys::fs::is_directory(target)) {
        llvm::errs() << "lshaz scan: '" << target
                     << "' is not a directory, .json file, or remote URL\n";
        return 3;
    }

    // Build ScanRequest.
    // Config autodiscovery: look for lshaz.config.yaml in the project root.
    if (args.configPath.empty() && !isCompileDB) {
        llvm::SmallString<256> candidate(target);
        llvm::sys::path::append(candidate, "lshaz.config.yaml");
        if (llvm::sys::fs::exists(candidate)) {
            args.configPath = std::string(candidate);
            llvm::errs() << "lshaz: using config " << candidate << "\n";
        }
    }

    Config cfg = args.configPath.empty()
        ? Config::defaults()
        : Config::loadFromFile(args.configPath);

    if (!args.allocator.empty())
        cfg.linkedAllocator = args.allocator;
    cfg.minSeverity = parseSeverity(args.minSeverity);

    ScanRequest request;
    request.config = cfg;

    if (isCompileDB) {
        request.compileDBPath = target;
    } else {
        request.workingDirectory = target;
        if (!args.compileDBPath.empty())
            request.compileDBPath = args.compileDBPath;
    }

    request.ir.enabled = !args.noIR;
    request.ir.optLevel = args.irOpt;
    request.ir.cacheEnabled = !args.noIRCache;
    request.ir.maxJobs = args.irJobs;
    request.ir.batchSize = args.irBatchSize;

    request.feedback.calibrationStorePath = args.calibrationStore;
    request.feedback.pmuTracePath = args.pmuTrace;
    request.feedback.pmuPriorsPath = args.pmuPriors;

    request.filter.minSeverity = cfg.minSeverity;
    request.filter.minEvidenceTier = parseEvidenceTier(args.minEvidence);
    request.filter.maxFiles = args.maxFiles;
    request.filter.includeFiles = args.includeFiles;
    request.filter.excludeFiles = args.excludeFiles;

    request.analysisJobs = args.jobs;

    request.perfProfilePath = args.perfProfile;
    request.hotnessThreshold = args.hotnessThreshold;

    if (args.format == "sarif")
        request.outputFormat = OutputFormat::SARIF;
    else if (args.format == "json")
        request.outputFormat = OutputFormat::JSON;
    else
        request.outputFormat = OutputFormat::CLI;

    // Execute pipeline.
    ScanPipeline pipeline([](const std::string &stage,
                             const std::string &detail) {
        llvm::errs() << "lshaz: [" << stage << "] " << detail << "\n";
    });

    auto result = pipeline.execute(request);

    // Summary on stderr.
    {
        unsigned ok = result.totalTUsAnalyzed - result.totalTUsFailed;
        llvm::errs() << "lshaz: " << ok << "/" << result.totalTUsAnalyzed
                     << " TU(s) parsed, " << result.diagnostics.size()
                     << " diagnostic(s)";
        if (result.totalTUsFailed > 0)
            llvm::errs() << ", " << result.totalTUsFailed << " failed";
        llvm::errs() << "\n";

        if (result.totalTUsFailed > 0) {
            unsigned cap = std::min(result.totalTUsFailed, 10u);
            for (unsigned i = 0; i < cap; ++i)
                llvm::errs() << "  failed: " << result.failedTUs[i] << "\n";
            if (result.totalTUsFailed > cap)
                llvm::errs() << "  ... and "
                             << (result.totalTUsFailed - cap) << " more\n";
        }
    }

    if (result.suppressedByCalibration > 0)
        llvm::errs() << "lshaz: suppressed " << result.suppressedByCalibration
                     << " diagnostic(s) via calibration feedback\n";

    int exitCode = emitOutput(result, request, args.format, args.outputFile);

    if (args.watch && !isCompileDB) {
        namespace fs = std::filesystem;

        auto snapshotMtimes = [](const std::string &dir)
            -> std::unordered_map<std::string, std::int64_t> {
            std::unordered_map<std::string, std::int64_t> mtimes;
            std::error_code ec;
            auto it = fs::recursive_directory_iterator(
                dir, fs::directory_options::skip_permission_denied, ec);
            if (ec) return mtimes;
            for (auto end = fs::recursive_directory_iterator(); it != end;
                 it.increment(ec)) {
                if (ec) break;
                if (!it->is_regular_file()) continue;
                auto ext = it->path().extension().string();
                if (ext != ".cpp" && ext != ".cc" && ext != ".cxx" &&
                    ext != ".c" && ext != ".h" && ext != ".hpp" &&
                    ext != ".hxx" && ext != ".yaml" && ext != ".yml")
                    continue;
                auto mtime = it->last_write_time()
                                 .time_since_epoch().count();
                mtimes[it->path().string()] = mtime;
            }
            return mtimes;
        };

        auto prev = snapshotMtimes(target);
        llvm::errs() << "lshaz: [watch] monitoring " << prev.size()
                     << " files (interval: " << args.watchInterval << "s)\n";

        while (true) {
            std::this_thread::sleep_for(
                std::chrono::seconds(args.watchInterval));

            auto curr = snapshotMtimes(target);
            bool changed = (curr.size() != prev.size());
            if (!changed) {
                for (const auto &[path, mtime] : curr) {
                    auto it = prev.find(path);
                    if (it == prev.end() || it->second != mtime) {
                        changed = true;
                        break;
                    }
                }
            }

            if (!changed) continue;

            llvm::errs() << "lshaz: [watch] change detected, re-scanning...\n";
            prev = curr;

            result = pipeline.execute(request);

            if (result.suppressedByCalibration > 0)
                llvm::errs() << "lshaz: suppressed "
                             << result.suppressedByCalibration
                             << " diagnostic(s) via calibration feedback\n";

            exitCode = emitOutput(result, request, args.format, args.outputFile);
        }
    }

    // Cleanup cloned repo if we created one.
    RepoProvider::cleanup(repoAcq);

    return exitCode;
}

} // namespace lshaz
