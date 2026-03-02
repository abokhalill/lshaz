// Contract tests for JSON and SARIF output schema.
//
// Validates that the output formatters produce deterministic, schema-versioned
// output with all required fields present. Run as a standalone binary.
// Returns 0 on success, 1 on contract violation.

#include "faultline/core/Diagnostic.h"
#include "faultline/core/ExecutionMetadata.h"
#include "faultline/core/Version.h"
#include "faultline/output/OutputFormatter.h"

#include <cassert>
#include <cmath>
#include <cstdlib>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

int failures = 0;

void check(bool cond, const char *msg) {
    if (!cond) {
        std::cerr << "FAIL: " << msg << "\n";
        ++failures;
    }
}

bool contains(const std::string &haystack, const std::string &needle) {
    return haystack.find(needle) != std::string::npos;
}

faultline::Diagnostic makeDiag(const char *rule, const char *func,
                                const char *file, unsigned line) {
    faultline::Diagnostic d;
    d.ruleID = rule;
    d.title = std::string(rule) + " test diagnostic";
    d.severity = faultline::Severity::High;
    d.confidence = 0.85;
    d.evidenceTier = faultline::EvidenceTier::Likely;
    d.location.file = file;
    d.location.line = line;
    d.location.column = 5;
    d.functionName = func;
    d.hardwareReasoning = "Test hardware reasoning";
    d.structuralEvidence = "Test structural evidence";
    d.mitigation = "Test mitigation";
    d.escalations.push_back("test-escalation");
    return d;
}

faultline::ExecutionMetadata makeMeta() {
    faultline::ExecutionMetadata meta;
    meta.toolVersion = faultline::kToolVersion;
    meta.configPath = "/tmp/test.yaml";
    meta.irOptLevel = "O0";
    meta.irEnabled = true;
    meta.timestampEpochSec = 1700000000;
    meta.sourceFiles = {"test.cpp"};
    return meta;
}

// --- JSON contract tests ---

void testJSONBasicSchema() {
    std::vector<faultline::Diagnostic> diags = {
        makeDiag("FL001", "foo", "test.cpp", 10),
        makeDiag("FL012", "bar::baz", "test.cpp", 42),
    };

    faultline::JSONOutputFormatter fmt;
    std::string out = fmt.format(diags);

    check(contains(out, "\"version\""), "JSON: missing 'version' field");
    check(contains(out, "\"schemaVersion\""), "JSON: missing 'schemaVersion' field");
    check(contains(out, std::string("\"") + faultline::kOutputSchemaVersion + "\""),
          "JSON: schemaVersion value mismatch");
    check(contains(out, "\"diagnostics\""), "JSON: missing 'diagnostics' array");
    check(contains(out, "\"ruleID\""), "JSON: missing 'ruleID' in diagnostic");
    check(contains(out, "\"title\""), "JSON: missing 'title' in diagnostic");
    check(contains(out, "\"severity\""), "JSON: missing 'severity' in diagnostic");
    check(contains(out, "\"confidence\""), "JSON: missing 'confidence' in diagnostic");
    check(contains(out, "\"evidenceTier\""), "JSON: missing 'evidenceTier' in diagnostic");
    check(contains(out, "\"location\""), "JSON: missing 'location' in diagnostic");
    check(contains(out, "\"file\""), "JSON: missing 'file' in location");
    check(contains(out, "\"line\""), "JSON: missing 'line' in location");
    check(contains(out, "\"column\""), "JSON: missing 'column' in location");
    check(contains(out, "\"functionName\""), "JSON: missing 'functionName' in diagnostic");
    check(contains(out, "\"hardwareReasoning\""), "JSON: missing 'hardwareReasoning'");
    check(contains(out, "\"structuralEvidence\""), "JSON: missing 'structuralEvidence'");
    check(contains(out, "\"mitigation\""), "JSON: missing 'mitigation'");
    check(contains(out, "\"escalations\""), "JSON: missing 'escalations'");
}

void testJSONWithMetadata() {
    std::vector<faultline::Diagnostic> diags = {
        makeDiag("FL002", "process", "engine.h", 100),
    };
    auto meta = makeMeta();

    faultline::JSONOutputFormatter fmt;
    std::string out = fmt.format(diags, meta);

    check(contains(out, "\"schemaVersion\""), "JSON+meta: missing 'schemaVersion'");
    check(contains(out, "\"metadata\""), "JSON+meta: missing 'metadata' object");
    check(contains(out, "\"timestamp\""), "JSON+meta: missing 'timestamp'");
    check(contains(out, "\"configPath\""), "JSON+meta: missing 'configPath'");
    check(contains(out, "\"irOptLevel\""), "JSON+meta: missing 'irOptLevel'");
    check(contains(out, "\"irEnabled\""), "JSON+meta: missing 'irEnabled'");
    check(contains(out, "\"sourceFiles\""), "JSON+meta: missing 'sourceFiles'");
    check(contains(out, "\"compilers\""), "JSON+meta: missing 'compilers'");
}

void testJSONDeterminism() {
    std::vector<faultline::Diagnostic> diags = {
        makeDiag("FL010", "tick", "x.cpp", 5),
        makeDiag("FL020", "alloc", "x.cpp", 50),
    };

    faultline::JSONOutputFormatter fmt;
    std::string a = fmt.format(diags);
    std::string b = fmt.format(diags);
    check(a == b, "JSON: non-deterministic output across calls");
}

void testJSONEmptyDiagnostics() {
    std::vector<faultline::Diagnostic> empty;
    faultline::JSONOutputFormatter fmt;
    std::string out = fmt.format(empty);

    check(contains(out, "\"schemaVersion\""), "JSON empty: missing 'schemaVersion'");
    check(contains(out, "\"diagnostics\": ["), "JSON empty: missing empty diagnostics array");
}

// --- SARIF contract tests ---

void testSARIFBasicSchema() {
    std::vector<faultline::Diagnostic> diags = {
        makeDiag("FL001", "foo", "test.cpp", 10),
    };

    faultline::SARIFOutputFormatter fmt;
    std::string out = fmt.format(diags);

    check(contains(out, "\"$schema\""), "SARIF: missing '$schema'");
    check(contains(out, "sarif-schema-2.1.0"), "SARIF: wrong schema URL");
    check(contains(out, "\"version\": \"2.1.0\""), "SARIF: wrong SARIF version");
    check(contains(out, "\"runs\""), "SARIF: missing 'runs'");
    check(contains(out, "\"tool\""), "SARIF: missing 'tool'");
    check(contains(out, "\"driver\""), "SARIF: missing 'driver'");
    check(contains(out, "\"name\": \"faultline\""), "SARIF: wrong tool name");
    check(contains(out, "\"outputSchemaVersion\""), "SARIF: missing outputSchemaVersion");
    check(contains(out, faultline::kOutputSchemaVersion),
          "SARIF: outputSchemaVersion value mismatch");
    check(contains(out, "\"rules\""), "SARIF: missing 'rules'");
    check(contains(out, "\"results\""), "SARIF: missing 'results'");
    check(contains(out, "\"ruleId\""), "SARIF: missing 'ruleId' in result");
    check(contains(out, "\"level\""), "SARIF: missing 'level' in result");
    check(contains(out, "\"message\""), "SARIF: missing 'message' in result");
    check(contains(out, "\"locations\""), "SARIF: missing 'locations' in result");
    check(contains(out, "\"physicalLocation\""), "SARIF: missing 'physicalLocation'");
    check(contains(out, "\"artifactLocation\""), "SARIF: missing 'artifactLocation'");
    check(contains(out, "\"region\""), "SARIF: missing 'region'");
    check(contains(out, "\"startLine\""), "SARIF: missing 'startLine'");
    check(contains(out, "\"startColumn\""), "SARIF: missing 'startColumn'");
    check(contains(out, "\"logicalLocations\""), "SARIF: missing 'logicalLocations'");
    check(contains(out, "\"fullyQualifiedName\""), "SARIF: missing 'fullyQualifiedName'");
    check(contains(out, "\"confidence\""), "SARIF: missing 'confidence' property");
    check(contains(out, "\"evidenceTier\""), "SARIF: missing 'evidenceTier' property");
    check(contains(out, "\"mitigation\""), "SARIF: missing 'mitigation' property");
}

void testSARIFWithMetadata() {
    std::vector<faultline::Diagnostic> diags = {
        makeDiag("FL002", "process", "engine.h", 100),
    };
    auto meta = makeMeta();

    faultline::SARIFOutputFormatter fmt;
    std::string out = fmt.format(diags, meta);

    check(contains(out, "\"outputSchemaVersion\""), "SARIF+meta: missing outputSchemaVersion");
    check(contains(out, "\"invocations\""), "SARIF+meta: missing 'invocations'");
    check(contains(out, "\"executionSuccessful\""), "SARIF+meta: missing 'executionSuccessful'");
    check(contains(out, "\"timestampEpochSec\""), "SARIF+meta: missing timestamp");
    check(contains(out, "\"artifacts\""), "SARIF+meta: missing 'artifacts'");
}

void testSARIFDeterminism() {
    std::vector<faultline::Diagnostic> diags = {
        makeDiag("FL010", "tick", "x.cpp", 5),
    };

    faultline::SARIFOutputFormatter fmt;
    std::string a = fmt.format(diags);
    std::string b = fmt.format(diags);
    check(a == b, "SARIF: non-deterministic output across calls");
}

// --- Adversarial regression tests ---

void testJSONControlCharEscape() {
    faultline::Diagnostic d;
    d.ruleID = "FL001";
    d.title = "test\r\n\b\f\x01\x1f";
    d.severity = faultline::Severity::High;
    d.confidence = 0.5;
    d.evidenceTier = faultline::EvidenceTier::Likely;
    d.location.file = "test.cpp";
    d.location.line = 1;
    d.location.column = 1;
    d.hardwareReasoning = "reason\twith\ttabs";
    d.structuralEvidence = "ev";
    d.mitigation = "mit";

    faultline::JSONOutputFormatter fmt;
    std::string out = fmt.format({d});

    // RFC 8259: no raw control chars U+0000-U+001F in strings.
    for (size_t i = 0; i < out.size(); ++i) {
        unsigned char c = static_cast<unsigned char>(out[i]);
        if (c < 0x20 && c != '\n') {
            // Only raw \n allowed (structural JSON whitespace).
            // \r, \t, etc. inside string values must be escaped.
            // Check if this is inside a string value by looking for context.
            // Simplification: \t and \n in structural whitespace are OK,
            // but \r \b \f \x01 must never appear raw.
            if (c == '\t') continue; // could be structural indent
            std::string msg = "JSON: raw control char 0x" +
                std::to_string(c) + " at offset " + std::to_string(i);
            check(false, msg.c_str());
        }
    }

    // Verify escaped forms are present.
    check(contains(out, "\\r"), "JSON: missing \\r escape");
    check(contains(out, "\\b"), "JSON: missing \\b escape");
    check(contains(out, "\\f"), "JSON: missing \\f escape");
    check(contains(out, "\\u0001"), "JSON: missing \\u0001 escape");
    check(contains(out, "\\u001f"), "JSON: missing \\u001f escape");
}

void testJSONNaNInfConfidence() {
    auto d1 = makeDiag("FL001", "foo", "t.cpp", 1);
    d1.confidence = std::numeric_limits<double>::quiet_NaN();

    auto d2 = makeDiag("FL002", "bar", "t.cpp", 2);
    d2.confidence = std::numeric_limits<double>::infinity();

    auto d3 = makeDiag("FL010", "baz", "t.cpp", 3);
    d3.confidence = -std::numeric_limits<double>::infinity();

    faultline::JSONOutputFormatter jfmt;
    std::string jout = jfmt.format({d1, d2, d3});

    // JSON must not contain bare nan/inf numeric tokens.
    // Check for patterns that indicate actual numeric nan/inf, not substrings
    // like "Informational" or "information".
    check(!contains(jout, ": nan"), "JSON: contains ': nan' numeric token");
    check(!contains(jout, ": inf"), "JSON: contains ': inf' numeric token");
    check(!contains(jout, ": -inf"), "JSON: contains ': -inf' numeric token");
    check(!contains(jout, ": NaN"), "JSON: contains ': NaN' numeric token");
    check(!contains(jout, ": Infinity"), "JSON: contains ': Infinity' numeric token");

    faultline::SARIFOutputFormatter sfmt;
    std::string sout = sfmt.format({d1, d2, d3});

    check(!contains(sout, ": nan"), "SARIF: contains ': nan' numeric token");
    check(!contains(sout, ": inf"), "SARIF: contains ': inf' numeric token");
    check(!contains(sout, ": -inf"), "SARIF: contains ': -inf' numeric token");
    check(!contains(sout, ": NaN"), "SARIF: contains ': NaN' numeric token");
    check(!contains(sout, ": Infinity"), "SARIF: contains ': Infinity' numeric token");
}

void testJSONEmptyFunctionName() {
    auto d = makeDiag("FL001", "", "test.cpp", 10);
    d.functionName = ""; // explicitly empty

    faultline::JSONOutputFormatter fmt;
    std::string out = fmt.format({d});

    // functionName must always be present (even if empty string)
    // for schema consistency.
    check(contains(out, "\"functionName\""),
          "JSON: functionName omitted when empty (schema inconsistency)");
}

void testJSONStress() {
    std::vector<faultline::Diagnostic> diags;
    for (int i = 0; i < 10000; ++i) {
        auto d = makeDiag("FL001", "func", "file.cpp", i);
        d.confidence = static_cast<double>(i) / 10000.0;
        diags.push_back(std::move(d));
    }

    faultline::JSONOutputFormatter fmt;
    std::string a = fmt.format(diags);
    std::string b = fmt.format(diags);
    check(a == b, "JSON stress: non-deterministic output with 10K diagnostics");
    check(a.size() > 100000, "JSON stress: suspiciously small output for 10K diags");
    check(contains(a, "\"schemaVersion\""), "JSON stress: missing schemaVersion");
}

} // anonymous namespace

int main() {
    testJSONBasicSchema();
    testJSONWithMetadata();
    testJSONDeterminism();
    testJSONEmptyDiagnostics();

    testSARIFBasicSchema();
    testSARIFWithMetadata();
    testSARIFDeterminism();

    testJSONControlCharEscape();
    testJSONNaNInfConfidence();
    testJSONEmptyFunctionName();
    testJSONStress();

    if (failures > 0) {
        std::cerr << "\n" << failures << " contract test(s) FAILED\n";
        return 1;
    }

    std::cout << "All output schema contract tests passed.\n";
    return 0;
}
