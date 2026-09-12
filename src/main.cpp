// SPDX-License-Identifier: Apache-2.0
#include "cli/diff.h"
#include "cli/exp.h"
#include "cli/explain.h"
#include "cli/feedback.h"
#include "cli/fix.h"
#include "cli/hyp.h"
#include "cli/init.h"
#include "cli/observe.h"
#include "cli/scan.h"

#include "lshaz/core/version.h"

#include <llvm/Support/raw_ostream.h>

#include <cstring>
#include <csignal>
#include <unistd.h>

namespace {

void onInterrupt(int) {
    static const char msg[] = "\nlshaz: interrupted, no results written\n";
    ssize_t ignored = ::write(STDERR_FILENO, msg, sizeof(msg) - 1);
    (void)ignored;
    ::_exit(130);
}

} // namespace

int main(int argc, const char **argv) {
    std::signal(SIGINT, onInterrupt);
    std::signal(SIGTERM, onInterrupt);

    if (argc >= 2 && std::strcmp(argv[1], "scan") == 0)
        return lshaz::runScanCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "explain") == 0)
        return lshaz::runExplainCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "init") == 0)
        return lshaz::runInitCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "diff") == 0)
        return lshaz::runDiffCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "fix") == 0)
        return lshaz::runFixCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "hyp") == 0)
        return lshaz::runHypCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "exp") == 0)
        return lshaz::runExpCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "feedback") == 0)
        return lshaz::runFeedbackCommand(argc - 2, argv + 2);
    if (argc >= 2 && std::strcmp(argv[1], "observe") == 0)
        return lshaz::runObserveCommand(argc - 2, argv + 2);

    if (argc >= 2 && (std::strcmp(argv[1], "version") == 0 ||
                      std::strcmp(argv[1], "--version") == 0)) {
        llvm::outs() << lshaz::kToolName << " version " << lshaz::kToolVersion
                     << " (output schema " << lshaz::kOutputSchemaVersion << ")\n";
        return 0;
    }

    const bool askedForHelp =
        argc >= 2 && (std::strcmp(argv[1], "help") == 0 ||
                      std::strcmp(argv[1], "--help") == 0 ||
                      std::strcmp(argv[1], "-h") == 0);
    if (argc < 2 || askedForHelp) {
        llvm::raw_ostream &out = askedForHelp ? llvm::outs() : llvm::errs();
        out
            << "lshaz " << lshaz::kToolVersion << "\n"
            << "Static analysis for microarchitectural latency hazards in C++\n"
            << "\n"
            << "Usage:\n"
            << "  lshaz scan <path> [options]   Analyze a project\n"
            << "  lshaz fix <path> [options]    Auto-remediate fixable findings\n"
            << "  lshaz hyp <scan.json>         Construct latency hypotheses\n"
            << "  lshaz exp <scan.json> -o dir  Synthesize experiment bundles\n"
            << "  lshaz init [path]             Generate compile_commands.json and config\n"
            << "  lshaz diff <a.json> <b.json>  Compare two scan results\n"
            << "  lshaz feedback <dir> --store  Ingest experiment results\n"
            << "  lshaz observe --profile p ... Feed a hardware profile back\n"
            << "  lshaz explain [rule]          Show rule documentation\n"
            << "  lshaz version                 Print version\n"
            << "  lshaz help                    Show this help\n"
            << "\n"
            << "Run 'lshaz scan --help' for scan options.\n";
        return askedForHelp ? 0 : 3;
    }

    llvm::errs() << "lshaz: unknown command '" << argv[1] << "'\n\n"
                 << "Available commands: scan, fix, hyp, exp, feedback, init, diff, explain, version, help\n"
                 << "Run 'lshaz help' for usage.\n";
    return 3;
}
