// SPDX-License-Identifier: Apache-2.0
#include "DiffCommand.h"

#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <cstring>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace lshaz {

namespace {

struct DiagKey {
    std::string ruleID;
    std::string file;
    unsigned line = 0;

    bool operator<(const DiagKey &o) const {
        if (ruleID != o.ruleID) return ruleID < o.ruleID;
        if (file != o.file) return file < o.file;
        return line < o.line;
    }
    bool operator==(const DiagKey &o) const {
        return ruleID == o.ruleID && file == o.file && line == o.line;
    }
};

struct DiagEntry {
    DiagKey key;
    std::string severity;
    std::string title;
    double confidence = 0.0;
};

// Minimal JSON string extraction. Finds "key": "value" pairs.
// Handles backslash-escaped quotes within values.
std::string extractString(const std::string &json, const std::string &key) {
    std::string needle = "\"" + key + "\": \"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos += needle.size();
    // Scan for unescaped closing quote.
    for (size_t i = pos; i < json.size(); ++i) {
        if (json[i] == '\\') { ++i; continue; }
        if (json[i] == '"') return json.substr(pos, i - pos);
    }
    return {};
}

unsigned extractUnsigned(const std::string &json, const std::string &key) {
    std::string needle = "\"" + key + "\": ";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return 0;
    pos += needle.size();
    return static_cast<unsigned>(std::stoul(json.substr(pos)));
}

double extractDouble(const std::string &json, const std::string &key) {
    std::string needle = "\"" + key + "\": ";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return 0.0;
    pos += needle.size();
    return std::stod(json.substr(pos));
}

// Split JSON array of diagnostic objects. Finds top-level objects in
// the "diagnostics" array by brace-counting.
std::vector<std::string> splitDiagnostics(const std::string &json) {
    std::vector<std::string> result;
    std::string marker = "\"diagnostics\": [";
    auto start = json.find(marker);
    if (start == std::string::npos) return result;
    start += marker.size();

    int depth = 0;
    size_t objStart = std::string::npos;
    for (size_t i = start; i < json.size(); ++i) {
        char c = json[i];
        if (c == '{') {
            if (depth == 0) objStart = i;
            ++depth;
        } else if (c == '}') {
            --depth;
            if (depth == 0 && objStart != std::string::npos) {
                result.push_back(json.substr(objStart, i - objStart + 1));
                objStart = std::string::npos;
            }
        } else if (c == ']' && depth == 0) {
            break;
        }
    }
    return result;
}

std::vector<DiagEntry> parseDiagFile(const std::string &path) {
    auto bufOrErr = llvm::MemoryBuffer::getFile(path);
    if (!bufOrErr) {
        llvm::errs() << "lshaz diff: cannot read '" << path << "': "
                     << bufOrErr.getError().message() << "\n";
        return {};
    }

    std::string json = (*bufOrErr)->getBuffer().str();
    auto objects = splitDiagnostics(json);

    std::vector<DiagEntry> entries;
    entries.reserve(objects.size());
    for (const auto &obj : objects) {
        DiagEntry e;
        e.key.ruleID = extractString(obj, "ruleID");
        e.key.file = extractString(obj, "file");
        e.key.line = extractUnsigned(obj, "line");
        e.severity = extractString(obj, "severity");
        e.title = extractString(obj, "title");
        e.confidence = extractDouble(obj, "confidence");
        entries.push_back(std::move(e));
    }
    return entries;
}

void printDiffUsage() {
    llvm::errs()
        << "Usage: lshaz diff <before.json> <after.json>\n"
        << "\n"
        << "Compare two lshaz JSON scan results and report:\n"
        << "  - New findings (in after but not before)\n"
        << "  - Resolved findings (in before but not after)\n"
        << "  - Summary counts\n"
        << "\n"
        << "Options:\n"
        << "  --help    Show this help\n";
}

} // anonymous namespace

int runDiffCommand(int argc, const char **argv) {
    if (argc < 1) {
        printDiffUsage();
        return 3;
    }
    if (std::strcmp(argv[0], "--help") == 0 ||
        std::strcmp(argv[0], "-h") == 0) {
        printDiffUsage();
        return 0;
    }

    if (argc < 2) {
        llvm::errs() << "lshaz diff: expected two JSON files\n\n";
        printDiffUsage();
        return 3;
    }

    std::string beforePath = argv[0];
    std::string afterPath = argv[1];

    auto before = parseDiagFile(beforePath);
    auto after = parseDiagFile(afterPath);

    if (before.empty() && after.empty()) {
        llvm::outs() << "lshaz diff: both files have 0 diagnostics\n";
        return 0;
    }

    // Build multisets to handle duplicate keys correctly.
    std::multiset<DiagKey> beforeKeys, afterKeys;
    for (const auto &e : before) beforeKeys.insert(e.key);
    for (const auto &e : after) afterKeys.insert(e.key);

    // New: present in after more times than in before.
    std::vector<const DiagEntry *> newFindings;
    {
        auto remaining = beforeKeys;
        for (const auto &e : after) {
            auto it = remaining.find(e.key);
            if (it != remaining.end())
                remaining.erase(it);
            else
                newFindings.push_back(&e);
        }
    }

    // Resolved: present in before more times than in after.
    std::vector<const DiagEntry *> resolved;
    {
        auto remaining = afterKeys;
        for (const auto &e : before) {
            auto it = remaining.find(e.key);
            if (it != remaining.end())
                remaining.erase(it);
            else
                resolved.push_back(&e);
        }
    }

    unsigned unchanged = before.size() - resolved.size();

    // Output.
    if (!newFindings.empty()) {
        llvm::outs() << "New findings (" << newFindings.size() << "):\n";
        for (const auto *e : newFindings) {
            llvm::outs() << "  + [" << e->severity << "] " << e->key.ruleID
                         << " — " << e->title << "\n"
                         << "    " << e->key.file << ":" << e->key.line << "\n";
        }
        llvm::outs() << "\n";
    }

    if (!resolved.empty()) {
        llvm::outs() << "Resolved findings (" << resolved.size() << "):\n";
        for (const auto *e : resolved) {
            llvm::outs() << "  - [" << e->severity << "] " << e->key.ruleID
                         << " — " << e->title << "\n"
                         << "    " << e->key.file << ":" << e->key.line << "\n";
        }
        llvm::outs() << "\n";
    }

    llvm::outs() << "Summary: " << newFindings.size() << " new, "
                 << resolved.size() << " resolved, "
                 << unchanged << " unchanged\n";

    // Exit 0 if no new findings, 1 if new findings introduced.
    return newFindings.empty() ? 0 : 1;
}

} // namespace lshaz
