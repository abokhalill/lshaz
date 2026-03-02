#include "faultline/output/OutputFormatter.h"
#include "faultline/core/Version.h"

#include <cmath>
#include <sstream>

namespace faultline {

namespace {

double safeDouble(double v) {
    if (std::isnan(v) || std::isinf(v)) return 0.0;
    return v;
}

std::string sarifEscape(const std::string &s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x",
                             static_cast<unsigned>(static_cast<unsigned char>(c)));
                    out += buf;
                } else {
                    out += c;
                }
                break;
        }
    }
    return out;
}

std::string sarifLevel(Severity sev) {
    switch (sev) {
        case Severity::Critical: return "error";
        case Severity::High:     return "warning";
        case Severity::Medium:   return "note";
        default:                 return "note";
    }
}

} // anonymous namespace

std::string SARIFOutputFormatter::format(
    const std::vector<Diagnostic> &diagnostics) {

    std::ostringstream os;

    os << "{\n";
    os << "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json\",\n";
    os << "  \"version\": \"2.1.0\",\n";
    os << "  \"runs\": [{\n";

    // Tool descriptor.
    os << "    \"tool\": {\n";
    os << "      \"driver\": {\n";
    os << "        \"name\": \"faultline\",\n";
    os << "        \"version\": \"" << kToolVersion << "\",\n";
    os << "        \"informationUri\": \"https://github.com/abokhalill/faultline\",\n";
    os << "        \"properties\": { \"outputSchemaVersion\": \"" << kOutputSchemaVersion << "\" },\n";
    os << "        \"rules\": [";

    // Collect unique rules.
    std::vector<std::string> seenRules;
    for (const auto &d : diagnostics) {
        bool found = false;
        for (const auto &r : seenRules)
            if (r == d.ruleID) { found = true; break; }
        if (!found)
            seenRules.push_back(d.ruleID);
    }

    for (size_t i = 0; i < seenRules.size(); ++i) {
        const std::string &rid = seenRules[i];
        std::string title;
        std::string hwMechanism;
        for (const auto &d : diagnostics) {
            if (d.ruleID == rid) {
                title = d.title;
                hwMechanism = d.hardwareReasoning;
                break;
            }
        }
        os << "\n          {\n";
        os << "            \"id\": \"" << sarifEscape(rid) << "\",\n";
        os << "            \"shortDescription\": { \"text\": \"" << sarifEscape(title) << "\" },\n";
        os << "            \"helpUri\": \"https://github.com/abokhalill/faultline#" << sarifEscape(rid) << "\",\n";
        os << "            \"properties\": { \"tags\": [\"latency\", \"microarchitecture\"] }\n";
        os << "          }";
        if (i + 1 < seenRules.size()) os << ",";
    }

    os << "\n        ]\n";
    os << "      }\n";
    os << "    },\n";

    // Results.
    os << "    \"results\": [";

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto &d = diagnostics[i];

        os << "\n      {\n";
        os << "        \"ruleId\": \"" << sarifEscape(d.ruleID) << "\",\n";
        os << "        \"level\": \"" << sarifLevel(d.severity) << "\",\n";
        os << "        \"message\": { \"text\": \"" << sarifEscape(d.hardwareReasoning) << "\" },\n";

        // Location.
        os << "        \"locations\": [{\n";
        os << "          \"physicalLocation\": {\n";
        os << "            \"artifactLocation\": { \"uri\": \"" << sarifEscape(d.location.file) << "\" },\n";
        os << "            \"region\": {\n";
        os << "              \"startLine\": " << (d.location.line > 0 ? d.location.line : 1) << ",\n";
        os << "              \"startColumn\": " << (d.location.column > 0 ? d.location.column : 1) << "\n";
        os << "            }\n";
        os << "          }";

        if (!d.functionName.empty()) {
            os << ",\n          \"logicalLocations\": [{\n";
            os << "            \"fullyQualifiedName\": \"" << sarifEscape(d.functionName) << "\",\n";
            os << "            \"kind\": \"function\"\n";
            os << "          }]";
        }

        os << "\n        }],\n";

        // Properties: confidence, evidence tier, mitigation, escalations.
        os << "        \"properties\": {\n";
        os << "          \"confidence\": " << safeDouble(d.confidence) << ",\n";
        os << "          \"evidenceTier\": \"" << evidenceTierName(d.evidenceTier) << "\",\n";
        os << "          \"structuralEvidence\": \"" << sarifEscape(d.structuralEvidence) << "\",\n";
        os << "          \"mitigation\": \"" << sarifEscape(d.mitigation) << "\"";

        if (!d.escalations.empty()) {
            os << ",\n          \"escalations\": [";
            for (size_t j = 0; j < d.escalations.size(); ++j) {
                os << "\"" << sarifEscape(d.escalations[j]) << "\"";
                if (j + 1 < d.escalations.size()) os << ", ";
            }
            os << "]";
        }

        os << "\n        }\n";
        os << "      }";
        if (i + 1 < diagnostics.size()) os << ",";
    }

    os << "\n    ]\n";
    os << "  }]\n";
    os << "}\n";

    return os.str();
}

std::string SARIFOutputFormatter::format(
    const std::vector<Diagnostic> &diagnostics,
    const ExecutionMetadata &meta) {

    std::ostringstream os;

    os << "{\n";
    os << "  \"$schema\": \"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json\",\n";
    os << "  \"version\": \"2.1.0\",\n";
    os << "  \"runs\": [{\n";

    os << "    \"tool\": {\n";
    os << "      \"driver\": {\n";
    os << "        \"name\": \"faultline\",\n";
    os << "        \"version\": \"" << sarifEscape(meta.toolVersion) << "\",\n";
    os << "        \"informationUri\": \"https://github.com/abokhalill/faultline\",\n";
    os << "        \"properties\": { \"outputSchemaVersion\": \"" << kOutputSchemaVersion << "\" },\n";
    os << "        \"rules\": [";

    std::vector<std::string> seenRules;
    for (const auto &d : diagnostics) {
        bool found = false;
        for (const auto &r : seenRules)
            if (r == d.ruleID) { found = true; break; }
        if (!found)
            seenRules.push_back(d.ruleID);
    }

    for (size_t i = 0; i < seenRules.size(); ++i) {
        const std::string &rid = seenRules[i];
        std::string title;
        for (const auto &d : diagnostics) {
            if (d.ruleID == rid) { title = d.title; break; }
        }
        os << "\n          {\n";
        os << "            \"id\": \"" << sarifEscape(rid) << "\",\n";
        os << "            \"shortDescription\": { \"text\": \"" << sarifEscape(title) << "\" },\n";
        os << "            \"helpUri\": \"https://github.com/abokhalill/faultline#" << sarifEscape(rid) << "\",\n";
        os << "            \"properties\": { \"tags\": [\"latency\", \"microarchitecture\"] }\n";
        os << "          }";
        if (i + 1 < seenRules.size()) os << ",";
    }

    os << "\n        ]\n";
    os << "      }\n";
    os << "    },\n";

    // Invocations: execution provenance.
    os << "    \"invocations\": [{\n";
    os << "      \"executionSuccessful\": true,\n";
    os << "      \"properties\": {\n";
    os << "        \"timestampEpochSec\": " << meta.timestampEpochSec << ",\n";
    os << "        \"configPath\": \"" << sarifEscape(meta.configPath) << "\",\n";
    os << "        \"irOptLevel\": \"" << sarifEscape(meta.irOptLevel) << "\",\n";
    os << "        \"irEnabled\": " << (meta.irEnabled ? "true" : "false") << ",\n";
    os << "        \"compilers\": [";
    for (size_t i = 0; i < meta.compilers.size(); ++i) {
        os << "{\"path\": \"" << sarifEscape(meta.compilers[i].path) << "\"}";
        if (i + 1 < meta.compilers.size()) os << ", ";
    }
    os << "]\n";
    os << "      }\n";
    os << "    }],\n";

    // Artifacts.
    if (!meta.sourceFiles.empty()) {
        os << "    \"artifacts\": [";
        for (size_t i = 0; i < meta.sourceFiles.size(); ++i) {
            os << "\n      { \"location\": { \"uri\": \"" << sarifEscape(meta.sourceFiles[i]) << "\" } }";
            if (i + 1 < meta.sourceFiles.size()) os << ",";
        }
        os << "\n    ],\n";
    }

    // Results.
    os << "    \"results\": [";

    for (size_t i = 0; i < diagnostics.size(); ++i) {
        const auto &d = diagnostics[i];

        os << "\n      {\n";
        os << "        \"ruleId\": \"" << sarifEscape(d.ruleID) << "\",\n";
        os << "        \"level\": \"" << sarifLevel(d.severity) << "\",\n";
        os << "        \"message\": { \"text\": \"" << sarifEscape(d.hardwareReasoning) << "\" },\n";

        os << "        \"locations\": [{\n";
        os << "          \"physicalLocation\": {\n";
        os << "            \"artifactLocation\": { \"uri\": \"" << sarifEscape(d.location.file) << "\" },\n";
        os << "            \"region\": {\n";
        os << "              \"startLine\": " << (d.location.line > 0 ? d.location.line : 1) << ",\n";
        os << "              \"startColumn\": " << (d.location.column > 0 ? d.location.column : 1) << "\n";
        os << "            }\n";
        os << "          }";

        if (!d.functionName.empty()) {
            os << ",\n          \"logicalLocations\": [{\n";
            os << "            \"fullyQualifiedName\": \"" << sarifEscape(d.functionName) << "\",\n";
            os << "            \"kind\": \"function\"\n";
            os << "          }]";
        }

        os << "\n        }],\n";

        os << "        \"properties\": {\n";
        os << "          \"confidence\": " << safeDouble(d.confidence) << ",\n";
        os << "          \"evidenceTier\": \"" << evidenceTierName(d.evidenceTier) << "\",\n";
        os << "          \"structuralEvidence\": \"" << sarifEscape(d.structuralEvidence) << "\",\n";
        os << "          \"mitigation\": \"" << sarifEscape(d.mitigation) << "\"";

        if (!d.escalations.empty()) {
            os << ",\n          \"escalations\": [";
            for (size_t j = 0; j < d.escalations.size(); ++j) {
                os << "\"" << sarifEscape(d.escalations[j]) << "\"";
                if (j + 1 < d.escalations.size()) os << ", ";
            }
            os << "]";
        }

        os << "\n        }\n";
        os << "      }";
        if (i + 1 < diagnostics.size()) os << ",";
    }

    os << "\n    ]\n";
    os << "  }]\n";
    os << "}\n";

    return os.str();
}

} // namespace faultline
