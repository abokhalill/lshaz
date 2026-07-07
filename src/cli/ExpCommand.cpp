// SPDX-License-Identifier: Apache-2.0
#include "ExpCommand.h"
#include "ScanResultParser.h"

#include "lshaz/hypothesis/HypothesisConstructor.h"
#include "lshaz/hypothesis/ExperimentSynthesizer.h"
#include "lshaz/hypothesis/MeasurementPlan.h"

#include <llvm/Support/raw_ostream.h>

#include <cstring>

namespace lshaz {

int runExpCommand(int argc, const char **argv) {
    if (argc < 1 || (argc == 1 && std::strcmp(argv[0], "--help") == 0)) {
        llvm::errs()
            << "Usage: lshaz exp <scan-result.json> [options]\n\n"
            << "Synthesize experiment bundles from scan diagnostics.\n\n"
            << "Options:\n"
            << "  -o <dir>       Output directory (default: ./experiments)\n"
            << "  --rule <id>    Only generate for a specific rule ID\n"
            << "  --min-conf <f> Minimum confidence threshold (default: 0.5)\n"
            << "  --sku <name>   CPU SKU family (default: generic)\n"
            << "  --dry-run      Show what would be generated without writing\n"
            << "  --help         Show this help\n";
        return 0;
    }

    const char *inputPath = argv[0];
    std::string outputDir = "experiments";
    std::string filterRule;
    std::string skuFamily = "generic";
    double minConf = 0.5;
    bool dryRun = false;

    for (int i = 1; i < argc; ++i) {
        if ((std::strcmp(argv[i], "-o") == 0 ||
             std::strcmp(argv[i], "--output") == 0) && i + 1 < argc)
            outputDir = argv[++i];
        else if (std::strcmp(argv[i], "--rule") == 0 && i + 1 < argc)
            filterRule = argv[++i];
        else if (std::strcmp(argv[i], "--min-conf") == 0 && i + 1 < argc)
            minConf = std::stod(argv[++i]);
        else if (std::strcmp(argv[i], "--sku") == 0 && i + 1 < argc)
            skuFamily = argv[++i];
        else if (std::strcmp(argv[i], "--dry-run") == 0)
            dryRun = true;
    }

    std::vector<Diagnostic> diagnostics;
    std::string error;
    if (!parseScanResultFile(inputPath, diagnostics, error)) {
        llvm::errs() << "lshaz exp: " << error << "\n";
        return 1;
    }

    unsigned generated = 0;
    unsigned skipped = 0;

    for (const auto &d : diagnostics) {
        if (!filterRule.empty() && d.ruleID != filterRule) {
            ++skipped;
            continue;
        }
        if (d.confidence < minConf) {
            ++skipped;
            continue;
        }

        auto hyp = HypothesisConstructor::construct(d);
        if (!hyp) {
            llvm::errs() << "lshaz exp: no hypothesis template for "
                         << d.ruleID << " at " << d.location.file << ":"
                         << d.location.line << " — skipped\n";
            ++skipped;
            continue;
        }

        auto plan = MeasurementPlanGenerator::generate(*hyp, skuFamily);
        std::string expDir = outputDir + "/" + hyp->hypothesisId;

        if (dryRun) {
            llvm::outs() << "[dry-run] " << hyp->hypothesisId
                         << " -> " << expDir << "/\n"
                         << "  rule: " << d.ruleID
                         << "  hazard: " << hazardClassName(hyp->hazardClass)
                         << "  files: " << (plan.scripts.size() + 7) << "\n";
            ++generated;
            continue;
        }

        auto bundle = ExperimentSynthesizer::synthesize(*hyp, plan, expDir);
        if (!ExperimentSynthesizer::writeToDisk(bundle)) {
            llvm::errs() << "lshaz exp: failed to write " << expDir << "\n";
            continue;
        }

        llvm::outs() << "[ok] " << hyp->hypothesisId << " -> " << expDir << "/\n";
        ++generated;
    }

    llvm::outs() << "\n" << generated << " experiment(s) generated, "
                 << skipped << " skipped\n";
    return 0;
}

} // namespace lshaz
