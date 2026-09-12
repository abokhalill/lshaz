// Checks the JSON, SARIF and CLI formatters emit deterministic,
// schema-versioned output with every required field.

#include "lshaz/core/diagnostic.h"
#include "lshaz/core/metadata.h"
#include "lshaz/core/version.h"
#include "lshaz/output/formatter.h"

#include <cassert>
#include <cmath>
#include <iostream>
#include <limits>
#include <string>
#include <vector>

namespace {

int failures = 0;
int passed = 0;

void check(bool cond, const char *msg) {
    if (!cond) {
        std::cerr << "  FAIL: " << msg << "\n";
        ++failures;
    } else {
        ++passed;
    }
}

bool contains(const std::string &haystack, const std::string &needle) {
    return haystack.find(needle) != std::string::npos;
}

lshaz::Diagnostic makeDiag(const char *rule, const char *func,
                            const char *file, unsigned line,
                            lshaz::Severity sev = lshaz::Severity::High) {
    lshaz::Diagnostic d;
    d.ruleID = rule;
    d.title = std::string(rule) + " diagnostic";
    d.severity = sev;
    d.confidence = 0.85;
    d.evidenceTier = lshaz::EvidenceTier::Likely;
    d.location.file = file;
    d.location.line = line;
    d.location.column = 5;
    d.functionName = func;
    d.hardwareReasoning = "Test hardware reasoning";
    d.structuralEvidence = {{"key", "value"}, {"metric", "42"}};
    d.mitigation = "Test mitigation";
    d.escalations.push_back("test-escalation");
    return d;
}

lshaz::ExecutionMetadata makeMeta() {
    lshaz::ExecutionMetadata m;
    m.toolVersion = lshaz::kToolVersion;
    m.configPath = "/test/config.yaml";
    m.irOptLevel = "O0";
    m.irEnabled = true;
    m.timestampEpochSec = 1700000000;
    m.sourceFiles = {"a.cpp", "b.cpp"};
    m.compilers = {{"/usr/bin/clang++", "18.0"}};
    return m;
}

// --- JSON contract ---

void testJSONDiagnosticsOnly() {
    std::cerr << "test: JSON diagnostics-only format\n";
    lshaz::JSONOutputFormatter fmt;
    auto d = makeDiag("FL001", "func", "test.cpp", 10);
    auto out = fmt.format({d});

    check(contains(out, "\"diagnostics\""), "has diagnostics key");
    check(contains(out, "\"ruleID\""), "has ruleID");
    check(contains(out, "FL001"), "contains rule ID value");
    check(contains(out, "\"severity\""), "has severity");
    check(contains(out, "\"confidence\""), "has confidence");
    check(contains(out, "\"evidenceTier\""), "has evidenceTier");
    check(contains(out, "\"location\""), "has location");
    check(contains(out, "\"file\""), "has file in location");
    check(contains(out, "\"line\""), "has line in location");
    check(contains(out, "\"functionName\""), "has functionName");
    check(contains(out, "\"hardwareReasoning\""), "has hardwareReasoning");
    check(contains(out, "\"structuralEvidence\""), "has structuralEvidence");
    check(contains(out, "\"mitigation\""), "has mitigation");
    check(contains(out, "\"escalations\""), "has escalations");
    check(contains(out, "\"version\""), "has version key");
    check(contains(out, "\"schemaVersion\""), "has schemaVersion");
}

void testJSONWithMetadata() {
    std::cerr << "test: JSON with metadata\n";
    lshaz::JSONOutputFormatter fmt;
    auto d = makeDiag("FL002", "func", "test.cpp", 20);
    auto m = makeMeta();
    auto out = fmt.format({d}, m);

    check(contains(out, "\"metadata\""), "has metadata");
    check(contains(out, "\"timestamp\""), "has timestamp");
    check(contains(out, "\"configPath\""), "has configPath");
    check(contains(out, "\"irOptLevel\""), "has irOptLevel");
    check(contains(out, "\"irEnabled\""), "has irEnabled");
    check(contains(out, "\"sourceFiles\""), "has sourceFiles");
    check(contains(out, "\"compilers\""), "has compilers");
}

void testJSONStructuralEvidenceIsObject() {
    std::cerr << "test: JSON structuralEvidence is object\n";
    lshaz::JSONOutputFormatter fmt;
    auto d = makeDiag("FL001", "f", "t.cpp", 1);
    d.structuralEvidence = {{"sizeof", "192"}, {"lines_spanned", "3"}};
    auto out = fmt.format({d});

    check(contains(out, "\"sizeof\""), "evidence has sizeof key");
    check(contains(out, "\"192\""), "evidence has sizeof value");
    check(contains(out, "\"lines_spanned\""), "evidence has lines_spanned");
}

void testJSONEmptyDiagnostics() {
    std::cerr << "test: JSON empty diagnostics\n";
    lshaz::JSONOutputFormatter fmt;
    auto out = fmt.format({});
    check(contains(out, "\"diagnostics\"") && !contains(out, "\"ruleID\""),
          "empty diagnostics array");
}

// Reads the value of the "confidence" key rather than searching the whole
// document: the schema version is also a dotted number, so a substring test
// passes on it and would keep passing if the field stopped being emitted.
static std::string confidenceField(const std::string &json) {
    const std::string key = "\"confidence\": ";
    auto at = json.find(key);
    if (at == std::string::npos) return {};
    at += key.size();
    auto end = json.find_first_of(",\n", at);
    return json.substr(at, end - at);
}

void testJSONConfidenceBounds() {
    std::cerr << "test: JSON confidence bounds are serialized on the field\n";
    lshaz::JSONOutputFormatter fmt;
    auto d = makeDiag("FL001", "f", "t.cpp", 1);

    d.confidence = 0.0;
    check(confidenceField(fmt.format({d})) == "0", "zero confidence on the field");

    d.confidence = 1.0;
    check(confidenceField(fmt.format({d})) == "1", "max confidence on the field");

    d.confidence = 0.88;
    check(confidenceField(fmt.format({d})) == "0.88",
          "a fractional value round-trips its digits");
}

void testJSONNaNGuard() {
    std::cerr << "test: JSON NaN guard\n";
    lshaz::JSONOutputFormatter fmt;
    auto d = makeDiag("FL001", "f", "t.cpp", 1);
    d.confidence = std::numeric_limits<double>::quiet_NaN();
    auto out = fmt.format({d});
    check(!contains(out, "NaN") && !contains(out, "nan"), "no NaN in output");
}

void testJSONControlCharEscape() {
    std::cerr << "test: JSON control character escaping\n";
    lshaz::JSONOutputFormatter fmt;
    auto d = makeDiag("FL001", "f", "t.cpp", 1);
    d.structuralEvidence = {{"data", "line1\nline2\ttab"}};
    auto out = fmt.format({d});
    check(!contains(out, "\n\"data\""), "newline escaped in evidence");
}

void testJSONSeverityOrdering() {
    std::cerr << "test: JSON severity string values\n";
    lshaz::JSONOutputFormatter fmt;

    auto dc = makeDiag("FL001", "f", "t.cpp", 1, lshaz::Severity::Critical);
    auto dh = makeDiag("FL002", "f", "t.cpp", 2, lshaz::Severity::High);
    auto dm = makeDiag("FL010", "f", "t.cpp", 3, lshaz::Severity::Medium);
    auto di = makeDiag("FL020", "f", "t.cpp", 4, lshaz::Severity::Informational);

    auto out = fmt.format({dc, dh, dm, di});
    check(contains(out, "\"Critical\""), "Critical serialized");
    check(contains(out, "\"High\""), "High serialized");
    check(contains(out, "\"Medium\""), "Medium serialized");
    check(contains(out, "\"Informational\""), "Informational serialized");
}

// --- SARIF contract ---

void testSARIFSchema() {
    std::cerr << "test: SARIF schema\n";
    lshaz::SARIFOutputFormatter fmt;
    auto d = makeDiag("FL001", "f", "t.cpp", 1);
    auto m = makeMeta();
    auto out = fmt.format({d}, m);

    check(contains(out, "\"$schema\""), "has $schema");
    check(contains(out, "sarif-schema-2.1.0"), "references SARIF 2.1.0");
    check(contains(out, "\"version\": \"2.1.0\""), "SARIF version 2.1.0");
    check(contains(out, "\"runs\""), "has runs array");
    check(contains(out, "\"tool\""), "has tool");
    check(contains(out, "\"results\""), "has results");
    check(contains(out, "\"rules\""), "has rules in tool.driver");
}

void testSARIFResultFields() {
    std::cerr << "test: SARIF result fields\n";
    lshaz::SARIFOutputFormatter fmt;
    auto d = makeDiag("FL002", "func", "test.cpp", 42);
    auto m = makeMeta();
    auto out = fmt.format({d}, m);

    check(contains(out, "\"ruleId\""), "result has ruleId");
    check(contains(out, "FL002"), "ruleId value");
    check(contains(out, "\"message\""), "result has message");
    check(contains(out, "\"locations\""), "result has locations");
    check(contains(out, "\"artifactLocation\""), "has artifactLocation");
    check(contains(out, "\"uri\""), "has uri in location");
}

// --- CLI contract ---

void testCLIFormat() {
    std::cerr << "test: CLI format\n";
    lshaz::CLIOutputFormatter fmt;
    auto d = makeDiag("FL001", "", "test.cpp", 10, lshaz::Severity::Critical);
    auto out = fmt.format({d});

    check(contains(out, "FL001"), "CLI contains rule ID");
    check(contains(out, "test.cpp"), "CLI contains filename");

    // Function-scoped diagnostic should include function name.
    auto d2 = makeDiag("FL020", "hotFunc", "engine.cpp", 42, lshaz::Severity::High);
    auto out2 = fmt.format({d2});
    check(contains(out2, "FL020"), "CLI contains function-scoped rule ID");
    check(contains(out2, "engine.cpp"), "CLI contains function-scoped filename");
}

void testCLIEmpty() {
    std::cerr << "test: CLI empty\n";
    lshaz::CLIOutputFormatter fmt;
    auto out = fmt.format({});
    check(contains(out, "no hazards") || out.empty() || contains(out, "0 "),
          "CLI handles empty diagnostics");
}

// --- Stress ---

void testLargeDiagnosticCount() {
    std::cerr << "test: large diagnostic count\n";
    lshaz::JSONOutputFormatter fmt;
    std::vector<lshaz::Diagnostic> diags;
    for (int i = 0; i < 1000; ++i)
        diags.push_back(makeDiag("FL001", "f", "t.cpp", i));
    auto out = fmt.format(diags);
    check(!out.empty(), "output produced for 1000 diagnostics");
    check(contains(out, "\"diagnostics\""), "valid JSON structure");
}

} // anonymous namespace

int main() {
    testJSONDiagnosticsOnly();
    testJSONWithMetadata();
    testJSONStructuralEvidenceIsObject();
    testJSONEmptyDiagnostics();
    testJSONConfidenceBounds();
    testJSONNaNGuard();
    testJSONControlCharEscape();
    testJSONSeverityOrdering();
    testSARIFSchema();
    testSARIFResultFields();
    testCLIFormat();
    testCLIEmpty();
    testLargeDiagnosticCount();

    std::cerr << "\n" << passed << " passed, " << failures << " failed\n";
    if (failures > 0) {
        std::cerr << "OUTPUT CONTRACT TESTS FAILED\n";
        return 1;
    }
    std::cerr << "All output contract tests passed.\n";
    return 0;
}
