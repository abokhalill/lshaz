// SPDX-License-Identifier: Apache-2.0
#include "diff.h"

#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lshaz {

namespace {

struct DiagKey {
    std::string entity;  // type_name or functionName; stable across moves
    std::string ruleID;
    std::string file;
    unsigned line = 0;

    bool operator<(const DiagKey &o) const {
        if (ruleID != o.ruleID) return ruleID < o.ruleID;
        if (file != o.file) return file < o.file;
        if (entity != o.entity) return entity < o.entity;
        return entity.empty() ? line < o.line : false;
    }
    bool operator==(const DiagKey &o) const {
        if (ruleID != o.ruleID || file != o.file || entity != o.entity)
            return false;
        // Anonymous findings have only their position to identify them.
        return entity.empty() ? line == o.line : true;
    }
};

struct DiagEntry {
    DiagKey key;
    std::string severity;
    std::string title;
    double confidence = 0.0;
};

// Two scans of the same project usually come from different checkouts; a
// base build and a PR build, so their absolute roots differ. Keying on
// absolute paths then reports every finding as new and every old one as
// resolved, which is precisely backwards for the CI gate this command
// exists to be. Strip each scan's own common root so the comparison runs on
// project-relative paths.
void normalizePaths(std::vector<DiagEntry> &diags) {
    if (diags.empty()) return;
    std::string prefix = diags.front().key.file;
    for (const auto &d : diags) {
        size_t i = 0;
        while (i < prefix.size() && i < d.key.file.size() &&
               prefix[i] == d.key.file[i])
            ++i;
        prefix.resize(i);
        if (prefix.empty()) return;
    }
    // Only whole directory components are a root; a shared filename prefix
    // between sibling files is not.
    auto slash = prefix.rfind('/');
    if (slash == std::string::npos) return;
    prefix.resize(slash + 1);
    for (auto &d : diags)
        if (d.key.file.rfind(prefix, 0) == 0)
            d.key.file.erase(0, prefix.size());
}

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

struct ScanMeta {
    unsigned totalTUs = 0;
    unsigned failedTUs = 0;
    bool parsed = false;
};

struct ParsedScan {
    std::vector<DiagEntry> diags;
    ScanMeta meta;
};

ParsedScan parseDiagFile(const std::string &path) {
    auto bufOrErr = llvm::MemoryBuffer::getFile(path);
    if (!bufOrErr) {
        llvm::errs() << "lshaz diff: cannot read '" << path << "': "
                     << bufOrErr.getError().message() << "\n";
        return {};
    }

    std::string json = (*bufOrErr)->getBuffer().str();

    ParsedScan result;

    // Extract metadata from top-level JSON.
    auto metaPos = json.find("\"metadata\"");
    if (metaPos != std::string::npos) {
        // Find the metadata object boundaries.
        auto braceStart = json.find('{', metaPos);
        if (braceStart != std::string::npos) {
            int depth = 1;
            size_t braceEnd = braceStart + 1;
            for (; braceEnd < json.size() && depth > 0; ++braceEnd) {
                if (json[braceEnd] == '{') ++depth;
                else if (json[braceEnd] == '}') --depth;
            }
            std::string metaObj = json.substr(braceStart, braceEnd - braceStart);
            result.meta.totalTUs = extractUnsigned(metaObj, "totalTUs");
            result.meta.failedTUs = extractUnsigned(metaObj, "failedTUCount");
            result.meta.parsed = true;
        }
    }

    auto objects = splitDiagnostics(json);
    result.diags.reserve(objects.size());
    for (const auto &obj : objects) {
        DiagEntry e;
        e.key.ruleID = extractString(obj, "ruleID");
        e.key.file = extractString(obj, "file");
        e.key.line = extractUnsigned(obj, "line");
        // Identity is the entity the finding is about, not where it sits
        // today. Keying on the line number makes any refactor that moves a
        // struct read as one finding resolved and an identical one
        // introduced, which floods the gate with churn on exactly the
        // commits most worth reviewing. Line stays for display.
        e.key.entity = extractString(obj, "type_name");
        if (e.key.entity.empty())
            e.key.entity = extractString(obj, "functionName");
        e.severity = extractString(obj, "severity");
        e.title = extractString(obj, "title");
        e.confidence = extractDouble(obj, "confidence");
        result.diags.push_back(std::move(e));
    }
    normalizePaths(result.diags);
    return result;
}

void printMetaDiff(const ScanMeta &a, const ScanMeta &b) {
    if (!a.parsed && !b.parsed) return;

    llvm::outs() << "Metadata:\n";
    if (a.parsed && b.parsed) {
        int tuDelta = static_cast<int>(b.totalTUs) - static_cast<int>(a.totalTUs);
        int failDelta = static_cast<int>(b.failedTUs) - static_cast<int>(a.failedTUs);

        llvm::outs() << "  TUs analyzed: " << a.totalTUs << " -> " << b.totalTUs;
        if (tuDelta != 0)
            llvm::outs() << " (" << (tuDelta > 0 ? "+" : "") << tuDelta << ")";
        llvm::outs() << "\n";

        llvm::outs() << "  TUs failed:   " << a.failedTUs << " -> " << b.failedTUs;
        if (failDelta != 0)
            llvm::outs() << " (" << (failDelta > 0 ? "+" : "") << failDelta << ")";
        if (failDelta > 0)
            llvm::outs() << "  regression";
        llvm::outs() << "\n";
    } else {
        if (a.parsed)
            llvm::outs() << "  before: " << a.totalTUs << " TUs, "
                         << a.failedTUs << " failed\n";
        if (b.parsed)
            llvm::outs() << "  after:  " << b.totalTUs << " TUs, "
                         << b.failedTUs << " failed\n";
    }
    llvm::outs() << "\n";
}

void printDistribution(const char *label,
                       const std::map<std::string, int> &bm,
                       const std::map<std::string, int> &am) {
    std::set<std::string> keys;
    for (const auto &[k, _] : bm) keys.insert(k);
    for (const auto &[k, _] : am) keys.insert(k);

    bool headerPrinted = false;
    for (const auto &k : keys) {
        auto bi = bm.find(k);
        auto ai = am.find(k);
        int bv = bi != bm.end() ? bi->second : 0;
        int av = ai != am.end() ? ai->second : 0;
        if (bv == av) continue;
        if (!headerPrinted) { llvm::outs() << label << ":\n"; headerPrinted = true; }
        int delta = av - bv;
        llvm::outs() << "  " << k << ": " << bv << " \u2192 " << av
                     << " (" << (delta > 0 ? "+" : "") << delta << ")\n";
    }
    if (headerPrinted) llvm::outs() << "\n";
}

void printDiffUsage() {
    llvm::errs()
        << "Usage: lshaz diff <before.json> <after.json>\n"
        << "\n"
        << "Compare two lshaz JSON scan results and report:\n"
        << "  - Metadata delta (TU counts, failures)\n"
        << "  - Rule and severity distribution shifts\n"
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

    auto beforeScan = parseDiagFile(beforePath);
    auto afterScan = parseDiagFile(afterPath);
    auto &before = beforeScan.diags;
    auto &after = afterScan.diags;

    // Metadata comparison.
    printMetaDiff(beforeScan.meta, afterScan.meta);

    if (before.empty() && after.empty()) {
        llvm::outs() << "lshaz diff: both files have 0 diagnostics\n";
        return 0;
    }

    // Distribution shifts.
    {
        std::map<std::string, int> br, ar;
        for (const auto &e : before) ++br[e.key.ruleID];
        for (const auto &e : after) ++ar[e.key.ruleID];
        printDistribution("Rule distribution", br, ar);
    }
    {
        std::map<std::string, int> bs, as;
        for (const auto &e : before) ++bs[e.severity];
        for (const auto &e : after) ++as[e.severity];
        printDistribution("Severity distribution", bs, as);
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
                         << ", " << e->title << "\n"
                         << "    " << e->key.file << ":" << e->key.line << "\n";
        }
        llvm::outs() << "\n";
    }

    if (!resolved.empty()) {
        llvm::outs() << "Resolved findings (" << resolved.size() << "):\n";
        for (const auto *e : resolved) {
            llvm::outs() << "  - [" << e->severity << "] " << e->key.ruleID
                         << ", " << e->title << "\n"
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
