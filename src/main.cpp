// SPDX-License-Identifier: Apache-2.0
#include "cli/ExplainCommand.h"
#include "cli/InitCommand.h"
#include "cli/ScanCommand.h"

#include "lshaz/core/Config.h"
#include "lshaz/core/Severity.h"
#include "lshaz/core/Version.h"
#include "lshaz/output/OutputFormatter.h"
#include "lshaz/pipeline/ScanPipeline.h"

#include <clang/Tooling/CommonOptionsParser.h>
#include <llvm/Support/CommandLine.h>
#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>

#include <cstring>
#include <memory>
#include <string>

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
    llvm::cl::desc("Path to production PMU trace data (TSV, one sample per line). "
                    "Format: function<TAB>file<TAB>line<TAB>counter<TAB>value[<TAB>duration_ns]. "
                    "Lines starting with '#' are ignored. Multiple samples per "
                    "function are accumulated. Used for closed-loop hazard prior learning."),
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
    if (argc >= 2 && std::strcmp(argv[1], "scan") == 0)
        return lshaz::runScanCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "explain") == 0)
        return lshaz::runExplainCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "init") == 0)
        return lshaz::runInitCommand(argc - 2, argv + 2);

    // `lshaz version` as a first-class subcommand.
    if (argc >= 2 && (std::strcmp(argv[1], "version") == 0 ||
                      std::strcmp(argv[1], "--version") == 0)) {
        llvm::outs() << lshaz::kToolName << " version " << lshaz::kToolVersion
                     << " (output schema " << lshaz::kOutputSchemaVersion << ")\n";
        return 0;
    }

    // `lshaz help` or `lshaz` with no args.
    if (argc < 2 || std::strcmp(argv[1], "help") == 0 ||
        std::strcmp(argv[1], "--help") == 0 ||
        std::strcmp(argv[1], "-h") == 0) {
        llvm::outs()
            << "lshaz " << lshaz::kToolVersion << "\n"
            << "Static analysis for microarchitectural latency hazards in C++\n"
            << "\n"
            << "Usage:\n"
            << "  lshaz scan <path> [options]   Analyze a project\n"
            << "  lshaz init [path]             Generate compile_commands.json and config\n"
            << "  lshaz explain [rule]          Show rule documentation\n"
            << "  lshaz version                 Print version\n"
            << "  lshaz help                    Show this help\n"
            << "\n"
            << "Run 'lshaz scan --help' for scan options.\n";
        return 0;
    }

    // Legacy CLI: bare source files with `-- <flags>`.
    // Deprecated since 0.2.0, removal in 0.4.0.
    llvm::cl::SetVersionPrinter([](llvm::raw_ostream &OS) {
        OS << lshaz::kToolName << " version " << lshaz::kToolVersion
           << " (output schema " << lshaz::kOutputSchemaVersion << ")\n";
    });

    llvm::errs() << "lshaz: warning: legacy CLI is deprecated and will be "
                    "removed in 0.4.0.\n"
                    "  Equivalent: lshaz scan <path> --compile-db <db>\n"
                    "  Run 'lshaz scan --help' for the new interface.\n\n";

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
    cfg.minSeverity = parseSeverity(MinSev);
    if (!LinkedAllocator.empty())
        cfg.linkedAllocator = LinkedAllocator;

    // Build ScanRequest from CLI flags.
    lshaz::ScanRequest request;
    request.config = cfg;
    request.sourceFiles.assign(parser->getSourcePathList().begin(),
                               parser->getSourcePathList().end());

    // The legacy CLI uses CommonOptionsParser which wraps a CompilationDatabase.
    // ScanPipeline needs a compile_commands.json path. For the legacy path,
    // we write a temporary compile DB from the parser's compilation database
    // if no explicit path is available. This preserves backward compatibility
    // with the `-- <compiler flags>` fixed compilation database syntax.
    //
    // For now, pass the compilation database through directly by using
    // the legacy entry point that accepts a CompilationDatabase reference.
    // TODO: migrate to ScanPipeline::execute(request) once `scan` subcommand
    // provides an explicit compile_commands.json path.

    request.ir.enabled = !NoIR;
    request.ir.optLevel = IROpt.getValue();
    request.ir.cacheEnabled = !NoIRCache;
    request.ir.maxJobs = IRJobs.getValue();
    request.ir.batchSize = IRBatchSize.getValue();

    request.feedback.calibrationStorePath = CalibrationStore.getValue();
    request.feedback.pmuTracePath = PMUTracePath.getValue();
    request.feedback.pmuPriorsPath = PMUPriorsPath.getValue();

    request.filter.minSeverity = cfg.minSeverity;
    request.filter.minEvidenceTier = parseEvidenceTier(MinEvidence);

    request.perfProfilePath = PerfProfile.getValue();
    request.hotnessThreshold = HotnessThreshold.getValue();

    // Determine output format.
    std::string fmt = OutputFormat.getValue();
    if (JSONFlag && fmt == "cli")
        fmt = "json";
    if (fmt == "sarif")
        request.outputFormat = lshaz::OutputFormat::SARIF;
    else if (fmt == "json" || cfg.jsonOutput)
        request.outputFormat = lshaz::OutputFormat::JSON;
    else
        request.outputFormat = lshaz::OutputFormat::CLI;

    // Execute pipeline via legacy path (CompilationDatabase reference).
    lshaz::ScanPipeline pipeline([](const std::string &stage,
                                    const std::string &detail) {
        llvm::errs() << "lshaz: [" << stage << "] " << detail << "\n";
    });

    auto result = pipeline.executeLegacy(
        request, parser->getCompilations(), parser->getSourcePathList());

    // Format output.
    std::unique_ptr<lshaz::OutputFormatter> formatter;
    if (request.outputFormat == lshaz::OutputFormat::SARIF)
        formatter = std::make_unique<lshaz::SARIFOutputFormatter>();
    else if (request.outputFormat == lshaz::OutputFormat::JSON)
        formatter = std::make_unique<lshaz::JSONOutputFormatter>();
    else {
        if (fmt != "cli" && fmt != "json" && fmt != "sarif")
            llvm::errs() << "lshaz: warning: unknown format '" << fmt
                         << "', defaulting to cli\n";
        formatter = std::make_unique<lshaz::CLIOutputFormatter>();
    }

    std::string output = formatter->format(result.diagnostics, result.metadata);

    // Emit.
    std::string outputFile = OutputFile.getValue();
    if (outputFile.empty())
        outputFile = cfg.outputFile;

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
