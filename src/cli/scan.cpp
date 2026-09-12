// SPDX-License-Identifier: Apache-2.0
#include "scan.h"

#include "lshaz/core/config.h"
#include "lshaz/core/registry.h"
#include "lshaz/core/emitters.h"
#include "lshaz/core/version.h"
#include "lshaz/output/formatter.h"
#include "lshaz/pipeline/repo.h"
#include "lshaz/pipeline/scan_pipeline.h"

#include <clang/Tooling/CompilationDatabase.h>
#include <llvm/ADT/SmallVector.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/Path.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace lshaz {

namespace {

// Every ID the tool can emit: registered rules plus the reduce phase's own
// emitters, which have no Rule object behind them.
std::vector<std::string> allRuleIDs() {
    std::vector<std::string> ids;
    for (const auto &rule : RuleRegistry::instance().rules())
        ids.emplace_back(rule->getID());
    for (const auto &e : nonRuleEmitters())
        ids.emplace_back(e.id);
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    return ids;
}

// Nearest known ID by a one-pass edit distance, for the "did you mean" line.
std::string nearestRuleID(const std::string &want,
                          const std::vector<std::string> &known) {
    auto distance = [](const std::string &a, const std::string &b) {
        std::vector<size_t> prev(b.size() + 1), cur(b.size() + 1);
        for (size_t j = 0; j <= b.size(); ++j) prev[j] = j;
        for (size_t i = 1; i <= a.size(); ++i) {
            cur[0] = i;
            for (size_t j = 1; j <= b.size(); ++j)
                cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1,
                                   prev[j - 1] + (a[i - 1] != b[j - 1] ? 1 : 0)});
            prev = cur;
        }
        return prev[b.size()];
    };
    std::string best;
    size_t bestD = 3;  // beyond this it is a different name, not a typo
    for (const auto &k : known) {
        size_t d = distance(want, k);
        if (d < bestD) { bestD = d; best = k; }
    }
    return best;
}

// Returns false when an ID names no rule. Silently ignoring one meant a typo
// scanned everything and reported success, which is the filter answering a
// question it was not asked.
bool applyRuleFilter(Config &cfg, FilterOptions &filter,
                     const std::vector<std::string> &enabledRules) {
    if (enabledRules.empty()) return true;

    const std::vector<std::string> known = allRuleIDs();
    bool ok = true;
    for (const auto &want : enabledRules) {
        if (std::binary_search(known.begin(), known.end(), want)) continue;
        llvm::errs() << "lshaz: unknown rule '" << want << "'\n";
        const std::string near = nearestRuleID(want, known);
        if (!near.empty())
            llvm::errs() << "  did you mean '" << near << "'?\n";
        ok = false;
    }
    if (!ok) {
        llvm::errs() << "  run 'lshaz explain --list' for every rule ID\n";
        return false;
    }

    // Both halves are needed. Disabling registered rules skips the work;
    // the output filter is what reaches findings the reduce phase
    // synthesizes, which no Rule object produces.
    std::unordered_set<std::string> enabled(enabledRules.begin(),
                                             enabledRules.end());
    for (const auto &rule : RuleRegistry::instance().rules()) {
        std::string id(rule->getID());
        if (!enabled.count(id))
            cfg.disabledRules.push_back(id);
    }
    filter.onlyRules = enabledRules;
    return true;
}

struct ScanArgs {
    std::string target;           // path or URL
    std::string compileDBPath;
    std::string configPath;
    std::string format = "cli";
    bool formatGiven = false;   // "cli" is the default, not necessarily a choice
    std::string outputFile;
    std::string minSeverity = "Informational";
    std::string minEvidence = "speculative";
    // O2 by default: most hot findings refine differently at O2
    // differently at O2 (the refiner then judges what actually executes,
    // post-inlining), and O2 IR is cheaper to emit than O0 on template
    // C++. --ir-opt O0 remains available for debug-build parity.
    std::string irOpt = "O2";
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
    unsigned memoryLimitMB = 0;
    std::vector<std::string> includeFiles;
    std::vector<std::string> excludeFiles;
    bool noIR = false;
    bool noIRCache = false;
    bool noCache = false;
    std::string cacheDir;
    unsigned cacheMaxMB = 4096;
    bool watch = false;
    unsigned watchInterval = 2;
    bool trustBuildSystem = false;
    bool includeVendored = false;
    std::string changedFilesPath;
    std::string targetArch;
    std::string machineName;
    std::string workloadCyclesPerOp;
    std::vector<std::string> enabledRules;  // --rule FL001 (repeatable)
    bool help = false;
    std::vector<std::string> compilerFlags;
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
        << "  -C, --compile-db <path>  Explicit path to compile_commands.json\n"
        << "  -c, --config <path>      Path to lshaz.config.yaml\n"
        << "  -f, --format <fmt>       cli    full finding detail (default)\n"
        << "                           tidy   one line per finding, clang-tidy style\n"
        << "                           json   complete record, every evidence field\n"
        << "                           sarif  SARIF 2.1.0 for code-scanning UIs\n"
        << "  -o, --output <path>      Write output to file instead of stdout\n"
        << "  -s, --min-severity <lv>  Minimum severity (Informational|Medium|High|Critical)\n"
        << "  -e, --min-evidence <t>   Minimum evidence tier (proven|likely|speculative)\n"
        << "  -j, --jobs <N>           Parallel AST analysis jobs (default: nproc)\n"
        << "      --memory-limit-mb <N> Per-shard address-space cap "
           "(default: available/jobs)\n"
        << "  -n, --max-files <N>      Maximum translation units to analyze\n"
        << "  -I, --include <pattern>  Only analyze files matching pattern (repeatable)\n"
        << "  -X, --exclude <pattern>  Skip files matching pattern (repeatable)\n"
        << "  -r, --rule <id>          Only run specific rule (repeatable, e.g. FL001)\n"
        << "  -a, --target-arch <arch> Target architecture: x86-64, arm64, arm64-apple\n"
        << "  -w, --watch              Watch mode: re-scan on file changes\n"
        << "      --no-ir              Disable LLVM IR analysis pass\n"
        << "      --ir-opt <O0|O1|O2>  IR optimization level (default: O2)\n"
        << "      --ir-jobs <N>        Max parallel IR jobs (default: nproc)\n"
        << "      --ir-batch-size <N>  TUs per IR shard (default: 1)\n"
        << "      --no-ir-cache        Disable incremental IR cache\n"
        << "      --cache-dir <path>   Reuse per-TU results from <path> across scans\n"
        << "      --no-cache           Ignore --cache-dir for this run\n"
        << "      --cache-max-mb <N>   Cache size cap, pruned oldest first (default 4096)\n"
        << "      --perf-profile <path> Path to perf profile for hotness guidance\n"
        << "      --allocator <name>   Linked allocator (tcmalloc|jemalloc|mimalloc)\n"
        << "      --calibration-store <p> Calibration feedback store (JSON)\n"
        << "      --pmu-trace <file>   Production PMU trace ingestion\n"
        << "      --pmu-priors <file>  Persist/load Bayesian hazard priors\n"
        << "      --watch-interval <N> Seconds between polls (default: 2)\n"
        << "      --include-vendored   Analyze deps/, third_party/, vendor/ trees too\n"
        << "      --trust-build-system Allow cmake/meson/bear on cloned repos\n"
        << "      --changed-files <p>  Only scan TUs affected by files listed in <path>\n"
        << "  -h, --help               Show this help\n"
        << "\n"
        << "Single-file mode:\n"
        << "  lshaz scan <file.cpp> -- <compiler-flags>\n"
        << "  Analyzes a single file with explicit compiler flags.\n"
        << "\n"
        << "Exit Codes:\n"
        << "  0  Clean, no diagnostics\n"
        << "  1  Findings, diagnostics emitted\n"
        << "  2  Parse errors. One or more TUs failed to compile\n"
        << "  3  Fatal. Infrastructure failure (bad arguments, missing files)\n";
}

bool consumeArg(int &i, int argc, const char **argv, const char *flag,
                std::string &out, const char *shortFlag = nullptr) {
    if ((std::strcmp(argv[i], flag) == 0 ||
         (shortFlag && std::strcmp(argv[i], shortFlag) == 0)) &&
        i + 1 < argc) {
        out = argv[++i];
        return true;
    }
    return false;
}

bool consumeArgUnsigned(int &i, int argc, const char **argv, const char *flag,
                        unsigned &out, const char *shortFlag = nullptr) {
    std::string s;
    if (consumeArg(i, argc, argv, flag, s, shortFlag)) {
        out = static_cast<unsigned>(std::stoul(s));
        return true;
    }
    return false;
}

bool parseScanArgs(int argc, const char **argv, ScanArgs &args) {
    for (int i = 0; i < argc; ++i) {
        // Everything after -- is compiler flags (single-file mode).
        if (std::strcmp(argv[i], "--") == 0) {
            for (++i; i < argc; ++i)
                args.compilerFlags.push_back(argv[i]);
            break;
        }
        if (std::strcmp(argv[i], "--help") == 0 ||
            std::strcmp(argv[i], "-h") == 0) {
            args.help = true;
            return true;
        }
        if (consumeArg(i, argc, argv, "--compile-db", args.compileDBPath, "-C")) continue;
        if (consumeArg(i, argc, argv, "--config", args.configPath, "-c")) continue;
        if (consumeArg(i, argc, argv, "--format", args.format, "-f")) {
            args.formatGiven = true;
            continue;
        }
        if (consumeArg(i, argc, argv, "--output", args.outputFile, "-o")) continue;
        if (consumeArg(i, argc, argv, "--min-severity", args.minSeverity, "-s")) continue;
        if (consumeArg(i, argc, argv, "--min-evidence", args.minEvidence, "-e")) continue;
        if (consumeArg(i, argc, argv, "--ir-opt", args.irOpt)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--ir-jobs", args.irJobs)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--ir-batch-size", args.irBatchSize)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--jobs", args.jobs, "-j")) continue;
        if (consumeArgUnsigned(i, argc, argv, "--memory-limit-mb",
                               args.memoryLimitMB)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--max-files", args.maxFiles, "-n")) continue;
        { std::string v; if (consumeArg(i, argc, argv, "--include", v, "-I")) { args.includeFiles.push_back(v); continue; } }
        { std::string v; if (consumeArg(i, argc, argv, "--exclude", v, "-X")) { args.excludeFiles.push_back(v); continue; } }
        if (consumeArg(i, argc, argv, "--perf-profile", args.perfProfile)) continue;
        if (consumeArg(i, argc, argv, "--allocator", args.allocator)) continue;
        if (consumeArg(i, argc, argv, "--calibration-store", args.calibrationStore)) continue;
        if (consumeArg(i, argc, argv, "--pmu-trace", args.pmuTrace)) continue;
        if (consumeArg(i, argc, argv, "--pmu-priors", args.pmuPriors)) continue;
        if (std::strcmp(argv[i], "--no-ir") == 0) { args.noIR = true; continue; }
        if (std::strcmp(argv[i], "--no-ir-cache") == 0) { args.noIRCache = true; continue; }
        if (std::strcmp(argv[i], "--no-cache") == 0) { args.noCache = true; continue; }
        if (consumeArg(i, argc, argv, "--cache-dir", args.cacheDir)) continue;
        if (consumeArgUnsigned(i, argc, argv, "--cache-max-mb", args.cacheMaxMB)) continue;
        if (std::strcmp(argv[i], "--watch") == 0 || std::strcmp(argv[i], "-w") == 0) { args.watch = true; continue; }
        if (std::strcmp(argv[i], "--include-vendored") == 0) {
            args.includeVendored = true;
            continue;
        }
        if (std::strcmp(argv[i], "--trust-build-system") == 0) { args.trustBuildSystem = true; continue; }
        if (consumeArg(i, argc, argv, "--changed-files", args.changedFilesPath)) continue;
        if (consumeArg(i, argc, argv, "--target-arch", args.targetArch, "-a")) continue;
        if (consumeArg(i, argc, argv, "--machine-name", args.machineName)) continue;
        if (consumeArg(i, argc, argv, "--workload-cycles-per-op", args.workloadCyclesPerOp)) continue;
        { std::string v; if (consumeArg(i, argc, argv, "--rule", v, "-r")) { args.enabledRules.push_back(v); continue; } }
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

std::string lowered(const std::string &s) {
    std::string out = s;
    for (char &c : out) c = static_cast<char>(std::tolower(
        static_cast<unsigned char>(c)));
    return out;
}

// Both of these used to fall back to the weakest value on an unrecognized
// name, so a typo asked to narrow and got everything back. Case is accepted
// in any form: --min-severity critical meaning Informational is the same
// silent widening by another route.
bool parseSeverity(const std::string &s, Severity &out) {
    const std::string k = lowered(s);
    if (k == "critical")      { out = Severity::Critical;      return true; }
    if (k == "high")          { out = Severity::High;          return true; }
    if (k == "medium")        { out = Severity::Medium;        return true; }
    if (k == "informational") { out = Severity::Informational; return true; }
    llvm::errs() << "lshaz: unknown severity '" << s
                 << "'\n  expected one of: Critical, High, Medium, "
                    "Informational\n";
    return false;
}

bool parseEvidenceTier(const std::string &s, EvidenceTier &out) {
    const std::string k = lowered(s);
    if (k == "proven")      { out = EvidenceTier::Proven;      return true; }
    if (k == "likely")      { out = EvidenceTier::Likely;      return true; }
    if (k == "speculative") { out = EvidenceTier::Speculative; return true; }
    llvm::errs() << "lshaz: unknown evidence tier '" << s
                 << "'\n  expected one of: proven, likely, speculative\n";
    return false;
}

// false on unknown arch (caller exits 3). shared by both scan modes so
// single-file mode cannot silently ignore an accepted flag.
bool applyTargetArch(Config &cfg, const std::string &arch) {
    if (arch.empty())
        return true;
    if (arch == "arm64") {
        cfg.targetArch = TargetArch::ARM64;
        cfg.cacheLineBytes = 64;
    } else if (arch == "arm64-apple") {
        cfg.targetArch = TargetArch::ARM64Apple;
        cfg.cacheLineBytes = 128;
        cfg.cacheLineSpanWarn = 128;
        cfg.cacheLineSpanCrit = 256;
    } else if (arch == "x86-64") {
        cfg.targetArch = TargetArch::X86_64;
    } else {
        llvm::errs() << "lshaz scan: unknown --target-arch '" << arch
                     << "' (valid: x86-64, arm64, arm64-apple)\n";
        return false;
    }
    return true;
}

int emitOutput(const ScanResult &result, const ScanRequest &request,
               const std::string &format, const std::string &outputFile) {
    std::unique_ptr<OutputFormatter> formatter;
    if (format == "sarif")
        formatter = std::make_unique<SARIFOutputFormatter>();
    else if (format == "json")
        formatter = std::make_unique<JSONOutputFormatter>();
    else if (format == "tidy")
        formatter = std::make_unique<ClangTidyOutputFormatter>();
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

    if (!args.format.empty() &&
        args.format != "cli" && args.format != "json" &&
        args.format != "sarif" && args.format != "tidy") {
        llvm::errs() << "lshaz scan: unknown format '" << args.format
                     << "'. Valid formats: cli, json, sarif, tidy\n";
        return 3;
    }

    // Single-file mode: lshaz scan <file> -- <compiler-flags>
    if (!args.compilerFlags.empty()) {
        std::string srcPath = args.target;
        if (!llvm::sys::fs::exists(srcPath)) {
            llvm::errs() << "lshaz scan: source file '" << srcPath
                         << "' not found\n";
            return 3;
        }
        llvm::SmallString<256> absSrc;
        llvm::sys::fs::real_path(srcPath, absSrc);
        srcPath = std::string(absSrc);

        clang::tooling::FixedCompilationDatabase fixedDB(
            ".", args.compilerFlags);

        ScanRequest request;
        request.config = args.configPath.empty()
            ? Config::defaults()
            : Config::loadFromFile(args.configPath);
        if (!args.allocator.empty())
            request.config.linkedAllocator = args.allocator;
        request.config.cacheDir = args.noCache ? std::string() : args.cacheDir;
        request.config.cacheMaxMB = args.cacheMaxMB;

        if (!applyTargetArch(request.config, args.targetArch))
            return 3;
        if (!parseSeverity(args.minSeverity, request.config.minSeverity))
            return 3;
        if (!applyRuleFilter(request.config, request.filter,
                             args.enabledRules))
            return 3;
        request.ir.enabled = !args.noIR;
        request.ir.optLevel = args.irOpt;
        request.ir.cacheEnabled = !args.noIRCache;
        request.ir.maxJobs = args.irJobs;
        request.ir.batchSize = args.irBatchSize;
        request.feedback.calibrationStorePath = args.calibrationStore;
        request.feedback.pmuTracePath = args.pmuTrace;
        request.feedback.pmuPriorsPath = args.pmuPriors;
        request.perfProfilePath = args.perfProfile;
        request.hotnessThreshold = args.hotnessThreshold;
        request.filter.minSeverity = request.config.minSeverity;
        if (!parseEvidenceTier(args.minEvidence, request.filter.minEvidenceTier))
            return 3;
        const std::string singleFormat =
            args.formatGiven ? args.format
                             : (request.config.jsonOutput ? "json" : "cli");

        bool isTTY = llvm::errs().is_displayed();
        ScanPipeline pipeline([isTTY](const std::string &stage,
                                      const std::string &detail) {
            if (stage == "progress" && isTTY)
                llvm::errs() << "\rlshaz: [" << stage << "] " << detail
                             << "        ";
            else
                llvm::errs() << "lshaz: [" << stage << "] " << detail << "\n";
        });

        auto result = pipeline.executeWithDB(
            request, fixedDB, {srcPath});

        if (isTTY) llvm::errs() << "\r";
        llvm::errs() << "lshaz: 1/1 TU(s) parsed, "
                     << result.diagnostics.size() << " diagnostic(s)\n";
        if (result.suppressedByCalibration > 0)
            llvm::errs() << "lshaz: suppressed "
                         << result.suppressedByCalibration
                         << " diagnostic(s) via calibration feedback\n";
        return emitOutput(result, request, singleFormat, args.outputFile);
    }

    // Resolve target: URL -> clone, .json -> compile DB, directory -> project root.
    std::string target = args.target;
    bool isCompileDB = false;
    RepoAcquisition repoAcq;

    bool isRemote = false;
    if (RepoProvider::isRemoteURL(target)) {
        isRemote = true;
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

    if (!applyTargetArch(cfg, args.targetArch))
        return 3;

    if (!args.allocator.empty())
        cfg.linkedAllocator = args.allocator;
    // Opt-in by name rather than a default location: a cache that nobody
    // asked for and nobody can see is the shape a stale result hides in.
    cfg.cacheDir = args.noCache ? std::string() : args.cacheDir;
    cfg.cacheMaxMB = args.cacheMaxMB;
    // Command line overrides the config file, so a one-off scan against a
    // different machine does not need its own file.
    if (!args.machineName.empty()) cfg.machineName = args.machineName;
    if (!args.workloadCyclesPerOp.empty())
        cfg.workloadCyclesPerOp =
            static_cast<unsigned>(std::stoul(args.workloadCyclesPerOp));
    if (!parseSeverity(args.minSeverity, cfg.minSeverity))
        return 3;

    ScanRequest request;
    request.config = cfg;

    // Local dirs: always trust. Remote clones: require explicit opt-in.
    request.trustBuildSystem = isRemote ? args.trustBuildSystem : true;

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
    if (!parseEvidenceTier(args.minEvidence, request.filter.minEvidenceTier))
        return 3;
    request.filter.maxFiles = args.maxFiles;
    if (!applyRuleFilter(request.config, request.filter, args.enabledRules))
        return 3;
    request.filter.includeFiles = args.includeFiles;
    request.filter.excludeFiles = args.excludeFiles;
    request.filter.skipVendored = cfg.skipVendored && !args.includeVendored;
    request.filter.vendorPatterns = cfg.vendorPathPatterns;

    if (!args.changedFilesPath.empty()) {
        auto bufOrErr = llvm::MemoryBuffer::getFile(args.changedFilesPath);
        if (!bufOrErr) {
            llvm::errs() << "lshaz scan: cannot read changed-files '"
                         << args.changedFilesPath << "': "
                         << bufOrErr.getError().message() << "\n";
            return 3;
        }
        llvm::StringRef contents = (*bufOrErr)->getBuffer();
        llvm::SmallVector<llvm::StringRef, 64> lines;
        contents.split(lines, '\n', /*MaxSplit=*/-1, /*KeepEmpty=*/false);
        for (auto &line : lines)
            request.filter.changedFiles.push_back(line.trim().str());
        llvm::errs() << "lshaz: incremental mode, "
                     << request.filter.changedFiles.size()
                     << " changed file(s)\n";
    }

    request.analysisJobs = args.jobs;
    request.memoryLimitMB = args.memoryLimitMB;

    request.perfProfilePath = args.perfProfile;
    request.hotnessThreshold = args.hotnessThreshold;

    // json_output was parsed and documented but read by nothing, so a config
    // asking for JSON silently got text. --format still wins, which is why the
    // flag has to record that it was given: "cli" is also the default.
    // json_output was parsed and documented but read by nothing, so a config
    // asking for JSON silently got text. --format still wins, which is why the
    // flag records that it was given: "cli" is also the default value.
    const std::string effectiveFormat =
        args.formatGiven ? args.format : (cfg.jsonOutput ? "json" : "cli");

    // Execute pipeline.
    bool isTTY = llvm::errs().is_displayed();
    ScanPipeline pipeline([isTTY](const std::string &stage,
                                  const std::string &detail) {
        if (stage == "progress" && isTTY)
            llvm::errs() << "\rlshaz: [" << stage << "] " << detail
                         << "        ";
        else
            llvm::errs() << "lshaz: [" << stage << "] " << detail << "\n";
    });

    auto result = pipeline.execute(request);

    // Summary on stderr.
    {
        if (isTTY) llvm::errs() << "\r";
        unsigned ok = result.totalTUsAnalyzed - result.totalTUsFailed;
        llvm::errs() << "lshaz: " << ok << "/" << result.totalTUsAnalyzed
                     << " TU(s) parsed, " << result.diagnostics.size()
                     << " diagnostic(s)";
        if (result.totalTUsFailed > 0)
            llvm::errs() << ", " << result.totalTUsFailed << " failed";
        llvm::errs() << "\n";
        if (result.vendoredTUsSkipped > 0)
            llvm::errs() << "lshaz: " << result.vendoredTUsSkipped
                         << " TU(s) skipped as vendored (vendor_path_patterns); "
                            "--include-vendored to analyze them\n";
        if (result.outOfTreeSuppressed > 0)
            llvm::errs() << "lshaz: " << result.outOfTreeSuppressed
                         << " finding(s) suppressed outside the scanned tree "
                            "(toolchain/dependency headers)\n";

        if (result.totalTUsFailed > 0) {
            unsigned cap = std::min(result.totalTUsFailed, 10u);
            for (unsigned i = 0; i < cap; ++i) {
                llvm::errs() << "  failed: " << result.failedTUs[i];
                if (i < result.failedTUErrors.size())
                    llvm::errs() << ", " << result.failedTUErrors[i];
                llvm::errs() << "\n";
            }
            if (result.totalTUsFailed > cap)
                llvm::errs() << "  ... and "
                             << (result.totalTUsFailed - cap) << " more\n";
        }

        // Coverage. Hot-path rules are silent without a hotness signal, and
        // that silence is indistinguishable from a clean result unless it is
        // stated.
        const auto &cov = result.coverage;
        // Hot as a share, not a count: it is summed per TU while the
        // function count is deduplicated, so printing both as counts reads as
        // more hot functions than functions.
        llvm::errs() << "lshaz: coverage "
                     << (cov.distinctFunctions ? cov.distinctFunctions
                                               : cov.functionsSeen)
                     << " function(s), " << cov.recordsSeen << " record(s), "
                     << (cov.functionsSeen
                             ? cov.functionsHot * 100 / cov.functionsSeen
                             : 0)
                     << "% hot";
        if (cov.functionsWithdrawnCold)
            llvm::errs() << ", " << cov.functionsWithdrawnCold
                         << " withdrawn cold after cross-TU resolution";
        llvm::errs() << "\n";
        // functionsHot is the map-phase verdict and counts Candidates the
        // reducer later refused, so it is printed next to the withdrawal count
        // rather than alone. No threshold warning here: the two are not
        // comparable quantities, since functionsHot counts functions and the
        // withdrawals only cover those that carried a finding.
        if (cov.functionsSeen > 0 && cov.functionsHot == 0)
            llvm::errs()
                << "lshaz: WARNING no function was marked hot, so every "
                   "hot-path rule was inert for this\n"
                   "  scan. Structural rules still ran. Supply one of: "
                   "--perf-profile <file>,\n"
                   "  hot_file_patterns/hot_function_patterns in "
                   "lshaz.config.yaml, or\n"
                   "  __attribute__((hot)) on the entry points.\n";
        // Inference seeds on entry points, so a library scanned on its own
        // has nothing to seed from. Saying "0.4% hot" without saying why
        // invites reading thin coverage as a clean codebase.
        else if (cov.functionsSeen > 1000 &&
                 cov.functionsHot * 100 < cov.functionsSeen)
            llvm::errs()
                << "lshaz: WARNING only " << cov.functionsHot << " of "
                << cov.functionsSeen << " function(s) are on a known hot "
                   "path, so hot-path rule\n"
                   "  coverage is thin. Hotness is inferred from entry "
                   "points (main, thread bodies);\n"
                   "  a library scanned without its application has none. "
                   "Supply --perf-profile or\n"
                   "  hot_function_patterns to measure rather than infer.\n";

        // Which rules produced nothing. "Looked and found nothing" and
        // "never ran" are the same output otherwise, and that ambiguity is
        // what let two rules sit silent through an entire audit.
        {
            std::unordered_set<std::string> fired;
            for (const auto &d : result.diagnostics)
                fired.insert(d.ruleID);
            // Rules the caller switched off are not inert; reporting them
            // as such would bury the ones that ran and saw nothing.
            std::unordered_set<std::string> off(cfg.disabledRules.begin(),
                                                cfg.disabledRules.end());
            std::vector<std::string> inert;
            for (const auto &r : RuleRegistry::instance().rules()) {
                std::string id(r->getID());
                if (!fired.count(id) && !off.count(id))
                    inert.push_back(id);
            }
            for (const auto &id : reducePhaseHazardRules())
                if (!fired.count(id) && !off.count(id))
                    inert.push_back(id);
            std::sort(inert.begin(), inert.end());
            if (!inert.empty()) {
                llvm::errs() << "lshaz: " << inert.size()
                             << " rule(s) produced no findings:";
                for (const auto &id : inert)
                    llvm::errs() << " " << id;
                llvm::errs() << "\n";
            }
        }
    }

    if (result.suppressedByCalibration > 0)
        llvm::errs() << "lshaz: suppressed " << result.suppressedByCalibration
                     << " diagnostic(s) via calibration feedback\n";

    int exitCode = emitOutput(result, request, effectiveFormat, args.outputFile);

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

            exitCode = emitOutput(result, request, effectiveFormat,
                                  args.outputFile);
        }
    }

    // Cleanup cloned repo if we created one.
    RepoProvider::cleanup(repoAcq);

    return exitCode;
}

} // namespace lshaz
