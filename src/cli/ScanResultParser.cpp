// SPDX-License-Identifier: Apache-2.0
#include "ScanResultParser.h"

#include <fstream>
#include <sstream>

namespace lshaz {

namespace {

// Tiny helpers — not a real JSON parser, just enough to read lshaz output.

void skipWS(const std::string &s, size_t &i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t'))
        ++i;
}

bool expect(const std::string &s, size_t &i, char c) {
    skipWS(s, i);
    if (i < s.size() && s[i] == c) { ++i; return true; }
    return false;
}

std::string parseString(const std::string &s, size_t &i) {
    skipWS(s, i);
    if (i >= s.size() || s[i] != '"') return {};
    ++i;
    std::string out;
    while (i < s.size() && s[i] != '"') {
        if (s[i] == '\\' && i + 1 < s.size()) {
            ++i;
            switch (s[i]) {
                case '"':  out += '"'; break;
                case '\\': out += '\\'; break;
                case 'n':  out += '\n'; break;
                case 'r':  out += '\r'; break;
                case 't':  out += '\t'; break;
                default:   out += s[i]; break;
            }
        } else {
            out += s[i];
        }
        ++i;
    }
    if (i < s.size()) ++i; // closing quote
    return out;
}

double parseNumber(const std::string &s, size_t &i) {
    skipWS(s, i);
    size_t start = i;
    if (i < s.size() && s[i] == '-') ++i;
    while (i < s.size() && (s[i] >= '0' && s[i] <= '9')) ++i;
    if (i < s.size() && s[i] == '.') { ++i; while (i < s.size() && (s[i] >= '0' && s[i] <= '9')) ++i; }
    if (i < s.size() && (s[i] == 'e' || s[i] == 'E')) { ++i; if (i < s.size() && (s[i] == '+' || s[i] == '-')) ++i; while (i < s.size() && (s[i] >= '0' && s[i] <= '9')) ++i; }
    return std::stod(s.substr(start, i - start));
}

unsigned parseUnsigned(const std::string &s, size_t &i) {
    return static_cast<unsigned>(parseNumber(s, i));
}

bool parseBool(const std::string &s, size_t &i) {
    skipWS(s, i);
    if (s.compare(i, 4, "true") == 0)  { i += 4; return true; }
    if (s.compare(i, 5, "false") == 0) { i += 5; return false; }
    return false;
}

// Skip any JSON value (string, number, object, array, bool, null).
void skipValue(const std::string &s, size_t &i) {
    skipWS(s, i);
    if (i >= s.size()) return;
    if (s[i] == '"') { parseString(s, i); return; }
    if (s[i] == '{') {
        ++i; int depth = 1;
        while (i < s.size() && depth > 0) {
            if (s[i] == '{') ++depth;
            else if (s[i] == '}') --depth;
            else if (s[i] == '"') { --i; parseString(s, i); continue; }
            ++i;
        }
        return;
    }
    if (s[i] == '[') {
        ++i; int depth = 1;
        while (i < s.size() && depth > 0) {
            if (s[i] == '[') ++depth;
            else if (s[i] == ']') --depth;
            else if (s[i] == '"') { --i; parseString(s, i); continue; }
            ++i;
        }
        return;
    }
    if (s.compare(i, 4, "true") == 0) { i += 4; return; }
    if (s.compare(i, 5, "false") == 0) { i += 5; return; }
    if (s.compare(i, 4, "null") == 0) { i += 4; return; }
    // number
    parseNumber(s, i);
}

Severity parseSeverity(const std::string &str) {
    if (str == "Critical")      return Severity::Critical;
    if (str == "High")          return Severity::High;
    if (str == "Medium")        return Severity::Medium;
    if (str == "Informational") return Severity::Informational;
    return Severity::Informational;
}

EvidenceTier parseEvidenceTier(const std::string &str) {
    if (str == "proven")      return EvidenceTier::Proven;
    if (str == "likely")      return EvidenceTier::Likely;
    if (str == "speculative") return EvidenceTier::Speculative;
    return EvidenceTier::Speculative;
}

// Parse a single diagnostic object starting after '{'.
Diagnostic parseDiagnostic(const std::string &s, size_t &i) {
    Diagnostic d;
    while (true) {
        skipWS(s, i);
        if (i >= s.size() || s[i] == '}') { if (i < s.size()) ++i; break; }
        std::string key = parseString(s, i);
        expect(s, i, ':');

        if (key == "ruleID")            d.ruleID = parseString(s, i);
        else if (key == "title")        d.title = parseString(s, i);
        else if (key == "severity")     d.severity = parseSeverity(parseString(s, i));
        else if (key == "confidence")   d.confidence = parseNumber(s, i);
        else if (key == "evidenceTier") d.evidenceTier = parseEvidenceTier(parseString(s, i));
        else if (key == "functionName") d.functionName = parseString(s, i);
        else if (key == "hardwareReasoning") d.hardwareReasoning = parseString(s, i);
        else if (key == "mitigation")   d.mitigation = parseString(s, i);
        else if (key == "location") {
            expect(s, i, '{');
            while (true) {
                skipWS(s, i);
                if (i >= s.size() || s[i] == '}') { if (i < s.size()) ++i; break; }
                std::string lk = parseString(s, i);
                expect(s, i, ':');
                if (lk == "file")        d.location.file = parseString(s, i);
                else if (lk == "line")   d.location.line = parseUnsigned(s, i);
                else if (lk == "column") d.location.column = parseUnsigned(s, i);
                else skipValue(s, i);
                expect(s, i, ',');
            }
        } else if (key == "structuralEvidence") {
            expect(s, i, '{');
            while (true) {
                skipWS(s, i);
                if (i >= s.size() || s[i] == '}') { if (i < s.size()) ++i; break; }
                std::string ek = parseString(s, i);
                expect(s, i, ':');
                std::string ev = parseString(s, i);
                d.structuralEvidence[ek] = ev;
                expect(s, i, ',');
            }
        } else if (key == "escalations") {
            expect(s, i, '[');
            while (true) {
                skipWS(s, i);
                if (i >= s.size() || s[i] == ']') { if (i < s.size()) ++i; break; }
                d.escalations.push_back(parseString(s, i));
                expect(s, i, ',');
            }
        } else {
            skipValue(s, i);
        }

        expect(s, i, ',');
    }
    return d;
}

} // anonymous namespace

bool parseScanResultFile(const std::string &path,
                         std::vector<Diagnostic> &out,
                         std::string &error) {
    std::ifstream ifs(path);
    if (!ifs) {
        error = "cannot open file: " + path;
        return false;
    }

    std::ostringstream ss;
    ss << ifs.rdbuf();
    std::string json = ss.str();
    size_t i = 0;

    // Find the "diagnostics" array.
    auto pos = json.find("\"diagnostics\"");
    if (pos == std::string::npos) {
        // Detect common misuse: hypothesis output fed to exp/hyp.
        if (json.find("\"hypotheses\"") != std::string::npos)
            error = "file contains hypothesis output, not scan results. "
                    "Pass the original scan JSON (from 'lshaz scan'), not "
                    "the output of 'lshaz hyp': " + path;
        else
            error = "no 'diagnostics' key found in " + path;
        return false;
    }
    i = pos + 13; // skip key
    expect(json, i, ':');
    if (!expect(json, i, '[')) {
        error = "expected '[' after diagnostics key";
        return false;
    }

    while (true) {
        skipWS(json, i);
        if (i >= json.size() || json[i] == ']') break;
        if (!expect(json, i, '{')) break;
        out.push_back(parseDiagnostic(json, i));
        expect(json, i, ',');
    }

    return true;
}

} // namespace lshaz
