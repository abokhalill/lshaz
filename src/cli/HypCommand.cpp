// SPDX-License-Identifier: Apache-2.0
#include "HypCommand.h"
#include "ScanResultParser.h"

#include "lshaz/hypothesis/HypothesisConstructor.h"
#include "lshaz/hypothesis/LatencyHypothesis.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/raw_ostream.h>

#include <cstring>
#include <sstream>

namespace lshaz {

namespace {

std::string hypothesisToJson(const LatencyHypothesis &h) {
    std::ostringstream os;
    os << "    {\n"
       << "      \"hypothesisId\": \"" << h.hypothesisId << "\",\n"
       << "      \"findingId\": \"" << h.findingId << "\",\n"
       << "      \"hazardClass\": \"" << hazardClassName(h.hazardClass) << "\",\n"
       << "      \"H0\": \"" << h.H0 << "\",\n"
       << "      \"H1\": \"" << h.H1 << "\",\n"
       << "      \"primaryMetric\": {\n"
       << "        \"name\": \"" << h.primaryMetric.name << "\",\n"
       << "        \"unit\": \"" << h.primaryMetric.unit << "\",\n"
       << "        \"percentile\": \"" << h.primaryMetric.percentile << "\"\n"
       << "      },\n"
       << "      \"minimumDetectableEffect\": " << h.minimumDetectableEffect << ",\n"
       << "      \"significanceLevel\": " << h.significanceLevel << ",\n"
       << "      \"power\": " << h.power << ",\n"
       << "      \"evidenceTier\": \"" << evidenceTierName(h.evidenceTier) << "\",\n"
       << "      \"verdict\": \"" << verdictName(h.verdict) << "\"\n"
       << "    }";
    return os.str();
}

} // anonymous namespace

int runHypCommand(int argc, const char **argv) {
    if (argc < 1 || (argc == 1 && std::strcmp(argv[0], "--help") == 0)) {
        llvm::errs()
            << "Usage: lshaz hyp <scan-result.json> [options]\n\n"
            << "Construct latency hypotheses from scan diagnostics.\n\n"
            << "Options:\n"
            << "  -o, --output <file>  Write output to file (default: stdout)\n"
            << "  --rule <id>          Only hypothesize for a specific rule ID\n"
            << "  --min-conf <f>       Minimum confidence threshold (default: 0.0)\n"
            << "  --help               Show this help\n";
        return 0;
    }

    const char *inputPath = argv[0];
    std::string filterRule;
    std::string outputPath;
    double minConf = 0.0;

    for (int i = 1; i < argc; ++i) {
        if ((std::strcmp(argv[i], "-o") == 0 ||
             std::strcmp(argv[i], "--output") == 0) && i + 1 < argc)
            outputPath = argv[++i];
        else if (std::strcmp(argv[i], "--rule") == 0 && i + 1 < argc)
            filterRule = argv[++i];
        else if (std::strcmp(argv[i], "--min-conf") == 0 && i + 1 < argc)
            minConf = std::stod(argv[++i]);
    }

    std::vector<Diagnostic> diagnostics;
    std::string error;
    if (!parseScanResultFile(inputPath, diagnostics, error)) {
        llvm::errs() << "lshaz hyp: " << error << "\n";
        return 1;
    }

    std::vector<LatencyHypothesis> hypotheses;
    for (const auto &d : diagnostics) {
        if (!filterRule.empty() && d.ruleID != filterRule)
            continue;
        if (d.confidence < minConf)
            continue;
        if (auto h = HypothesisConstructor::construct(d))
            hypotheses.push_back(std::move(*h));
        else
            llvm::errs() << "lshaz hyp: no hypothesis template for "
                         << d.ruleID << " at " << d.location.file << ":"
                         << d.location.line << " — skipped\n";
    }

    // Select output stream.
    std::error_code ec;
    std::unique_ptr<llvm::raw_fd_ostream> fileStream;
    llvm::raw_ostream *out = &llvm::outs();
    if (!outputPath.empty()) {
        fileStream = std::make_unique<llvm::raw_fd_ostream>(
            outputPath, ec, llvm::sys::fs::OF_Text);
        if (ec) {
            llvm::errs() << "lshaz hyp: cannot open '" << outputPath
                         << "': " << ec.message() << "\n";
            return 1;
        }
        out = fileStream.get();
    }

    *out << "{\n"
         << "  \"hypotheses\": [\n";
    for (size_t i = 0; i < hypotheses.size(); ++i) {
        *out << hypothesisToJson(hypotheses[i]);
        if (i + 1 < hypotheses.size()) *out << ",";
        *out << "\n";
    }
    *out << "  ],\n"
         << "  \"totalDiagnostics\": " << diagnostics.size() << ",\n"
         << "  \"hypothesesGenerated\": " << hypotheses.size() << "\n"
         << "}\n";

    if (fileStream)
        llvm::errs() << "lshaz hyp: wrote " << hypotheses.size()
                     << " hypothesis(es) to " << outputPath << "\n";

    return 0;
}

} // namespace lshaz
