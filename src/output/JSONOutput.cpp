#include "faultline/output/OutputFormatter.h"
#include "faultline/core/Version.h"

#include <sstream>

namespace faultline {

namespace {

std::string escape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\t': out += "\\t";  break;
            default:   out += c;      break;
        }
    }
    return out;
}

} // anonymous namespace

std::string JSONOutputFormatter::format(const std::vector<Diagnostic> &diagnostics) {
    std::ostringstream os;
    os << "{\n";
    os << "  \"version\": \"" << kToolVersion << "\",\n";
    os << "  \"schemaVersion\": \"" << kOutputSchemaVersion << "\",\n";
    os << "  \"diagnostics\": [\n";

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto &d = diagnostics[i];
        os << "    {\n";
        os << "      \"ruleID\": \"" << escape(d.ruleID) << "\",\n";
        os << "      \"title\": \"" << escape(d.title) << "\",\n";
        os << "      \"severity\": \"" << severityToString(d.severity) << "\",\n";
        os << "      \"confidence\": " << d.confidence << ",\n";
        os << "      \"evidenceTier\": \"" << evidenceTierName(d.evidenceTier) << "\",\n";
        os << "      \"location\": {\n";
        os << "        \"file\": \"" << escape(d.location.file) << "\",\n";
        os << "        \"line\": " << d.location.line << ",\n";
        os << "        \"column\": " << d.location.column << "\n";
        os << "      },\n";
        if (!d.functionName.empty())
            os << "      \"functionName\": \"" << escape(d.functionName) << "\",\n";
        os << "      \"hardwareReasoning\": \"" << escape(d.hardwareReasoning) << "\",\n";
        os << "      \"structuralEvidence\": \"" << escape(d.structuralEvidence) << "\",\n";
        os << "      \"mitigation\": \"" << escape(d.mitigation) << "\",\n";

        os << "      \"escalations\": [";
        for (size_t j = 0; j < d.escalations.size(); ++j) {
            os << "\"" << escape(d.escalations[j]) << "\"";
            if (j + 1 < d.escalations.size()) os << ", ";
        }
        os << "]\n";

        os << "    }";
        if (i + 1 < diagnostics.size()) os << ",";
        os << "\n";
    }

    os << "  ]\n}\n";
    return os.str();
}

std::string JSONOutputFormatter::format(const std::vector<Diagnostic> &diagnostics,
                                        const ExecutionMetadata &meta) {
    std::ostringstream os;
    os << "{\n";
    os << "  \"version\": \"" << escape(meta.toolVersion) << "\",\n";
    os << "  \"schemaVersion\": \"" << kOutputSchemaVersion << "\",\n";
    os << "  \"metadata\": {\n";
    os << "    \"timestamp\": " << meta.timestampEpochSec << ",\n";
    os << "    \"configPath\": \"" << escape(meta.configPath) << "\",\n";
    os << "    \"irOptLevel\": \"" << escape(meta.irOptLevel) << "\",\n";
    os << "    \"irEnabled\": " << (meta.irEnabled ? "true" : "false") << ",\n";
    os << "    \"sourceFiles\": [";
    for (size_t i = 0; i < meta.sourceFiles.size(); ++i) {
        os << "\"" << escape(meta.sourceFiles[i]) << "\"";
        if (i + 1 < meta.sourceFiles.size()) os << ", ";
    }
    os << "],\n";
    os << "    \"compilers\": [";
    for (size_t i = 0; i < meta.compilers.size(); ++i) {
        os << "{\"path\": \"" << escape(meta.compilers[i].path) << "\"}";
        if (i + 1 < meta.compilers.size()) os << ", ";
    }
    os << "]\n";
    os << "  },\n";
    os << "  \"diagnostics\": [\n";

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto &d = diagnostics[i];
        os << "    {\n";
        os << "      \"ruleID\": \"" << escape(d.ruleID) << "\",\n";
        os << "      \"title\": \"" << escape(d.title) << "\",\n";
        os << "      \"severity\": \"" << severityToString(d.severity) << "\",\n";
        os << "      \"confidence\": " << d.confidence << ",\n";
        os << "      \"evidenceTier\": \"" << evidenceTierName(d.evidenceTier) << "\",\n";
        os << "      \"location\": {\n";
        os << "        \"file\": \"" << escape(d.location.file) << "\",\n";
        os << "        \"line\": " << d.location.line << ",\n";
        os << "        \"column\": " << d.location.column << "\n";
        os << "      },\n";
        if (!d.functionName.empty())
            os << "      \"functionName\": \"" << escape(d.functionName) << "\",\n";
        os << "      \"hardwareReasoning\": \"" << escape(d.hardwareReasoning) << "\",\n";
        os << "      \"structuralEvidence\": \"" << escape(d.structuralEvidence) << "\",\n";
        os << "      \"mitigation\": \"" << escape(d.mitigation) << "\",\n";

        os << "      \"escalations\": [";
        for (size_t j = 0; j < d.escalations.size(); ++j) {
            os << "\"" << escape(d.escalations[j]) << "\"";
            if (j + 1 < d.escalations.size()) os << ", ";
        }
        os << "]\n";

        os << "    }";
        if (i + 1 < diagnostics.size()) os << ",";
        os << "\n";
    }

    os << "  ]\n}\n";
    return os.str();
}

} // namespace faultline
