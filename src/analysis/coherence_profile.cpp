// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/coherence_profile.h"

#include <algorithm>
#include <cstdlib>
#include <set>
#include <sstream>

namespace lshaz {

namespace {

std::vector<std::string> tokens(const std::string &s) {
    std::vector<std::string> out;
    std::istringstream is(s);
    std::string t;
    while (is >> t) out.push_back(t);
    return out;
}

bool allDashes(const std::string &s) {
    bool any = false;
    for (char c : s) {
        if (c == '-') any = true;
        else if (c != ' ' && c != '\t' && c != '\r') return false;
    }
    return any;
}

bool isHex(const std::string &t) {
    return t.size() > 2 && t[0] == '0' && (t[1] == 'x' || t[1] == 'X');
}

bool isUInt(const std::string &t) {
    if (t.empty()) return false;
    for (char c : t)
        if (c < '0' || c > '9') return false;
    return true;
}

bool isPercent(const std::string &t) {
    return t.size() > 1 && t.back() == '%';
}

uint64_t toUInt(const std::string &t) {
    return std::strtoull(t.c_str(), nullptr, 0);
}

// Percentages carry two decimals, so scale by 100 and divide once at the
// end. Doing it in floating point would make the same report produce
// different counts on different libm versions.
uint64_t shareOf(const std::string &pct, uint64_t total) {
    if (total == 0) return 0;
    const auto dot = pct.find('.');
    uint64_t hundredths = 0;
    if (dot == std::string::npos) {
        hundredths = toUInt(pct.substr(0, pct.size() - 1)) * 100;
    } else {
        hundredths = toUInt(pct.substr(0, dot)) * 100;
        std::string frac = pct.substr(dot + 1, pct.size() - dot - 2);
        frac.resize(2, '0');
        hundredths += toUInt(frac);
    }
    return (hundredths * total + 5000) / 10000;
}

// Header field whose value is the trailing integer after a colon.
bool headerValue(const std::string &line, const char *label, uint64_t &out) {
    if (line.find(label) == std::string::npos) return false;
    const auto colon = line.rfind(':');
    if (colon == std::string::npos) return false;
    const auto v = tokens(line.substr(colon + 1));
    if (v.empty() || !isUInt(v[0])) return false;
    out = toUInt(v[0]);
    return true;
}

// The Source:Line column, whether or not the compiler left anything in it.
// A stripped library reports ??:0 and still occupies the column, so finding
// the column and reading it are separate questions: the first bounds the
// symbol, the second decides whether the access can be joined at all.
//
// Only the basename survives. The profiler sees whatever path DWARF holds,
// which is the build directory, and the analyzer sees the path it was
// pointed at; the basename is the part both agree on.
bool isSourceColumn(const std::string &t) {
    const auto colon = t.rfind(':');
    return colon != std::string::npos && colon + 1 < t.size() &&
           isUInt(t.substr(colon + 1));
}

bool splitSourceLine(const std::string &t, std::string &file, unsigned &line) {
    if (!isSourceColumn(t)) return false;
    const auto colon = t.rfind(':');
    std::string path = t.substr(0, colon);
    if (path.empty() || path == "??") return false;
    const auto slash = path.find_last_of('/');
    file = slash == std::string::npos ? path : path.substr(slash + 1);
    line = static_cast<unsigned>(toUInt(t.substr(colon + 1)));
    return !file.empty() && line != 0;
}

// The numeric prefix of a Pareto access row, up to and including the cpu
// count. Fixed width in every version that emits Source:Line at all.
//
//   5 shares, offset, node, pa-cnt, code-addr, 3 cycle columns, records, cpus
constexpr size_t kPrefix = 14;

bool parseAccessRow(const std::vector<std::string> &t, uint64_t lclHitm,
                    uint64_t rmtHitm, CoherenceAccess &out) {
    if (t.size() < kPrefix + 3) return false;
    for (size_t i = 0; i < 5; ++i)
        if (!isPercent(t[i])) return false;
    if (!isHex(t[5]) || !isHex(t[8])) return false;

    out.offset = static_cast<unsigned>(toUInt(t[5]));
    out.hitmSamples =
        shareOf(t[0], rmtHitm) + shareOf(t[1], lclHitm);
    out.hitmCycles = static_cast<unsigned>(toUInt(t[10]));
    out.records = toUInt(t[12]);

    // Symbol names contain spaces once anything is demangled, so the tail is
    // read from the right: the Source:Line token anchors it, Object sits
    // immediately before, and everything from the map marker to there is the
    // symbol.
    size_t src = 0;
    for (size_t i = t.size(); i-- > kPrefix + 2;) {
        if (isSourceColumn(t[i])) { src = i; break; }
    }
    if (!src) return false;

    out.object = t[src - 1];

    // No debug line for this site, which happens for stripped libraries and
    // for anything the compiler inlined past. The samples are real, so the
    // access is kept and counts toward the total. It simply cannot join to a
    // finding, and the difference between that and a site nobody measured is
    // the whole point of keeping it.
    splitSourceLine(t[src], out.file, out.line);
    const size_t symEnd = src - 1;

    size_t symStart = kPrefix;
    if (t[symStart].size() == 3 && t[symStart][0] == '[') ++symStart;
    for (size_t i = symStart; i < symEnd; ++i) {
        if (!out.symbol.empty()) out.symbol += ' ';
        out.symbol += t[i];
    }
    return true;
}

} // namespace

unsigned CoherenceLine::contendedOffsets() const {
    std::set<unsigned> offs;
    for (const auto &a : accesses)
        if (a.hitmSamples) offs.insert(a.offset);
    return static_cast<unsigned>(offs.size());
}

unsigned CoherenceProfile::meanHitmCycles() const {
    uint64_t weighted = 0, samples = 0;
    for (const auto &l : lines)
        for (const auto &a : l.accesses) {
            if (!a.hitmSamples || !a.hitmCycles) continue;
            weighted += a.hitmSamples * a.hitmCycles;
            samples += a.hitmSamples;
        }
    return samples ? static_cast<unsigned>((weighted + samples / 2) / samples)
                   : 0;
}

bool parsePerfC2CReport(const std::string &text, CoherenceProfile &out,
                        std::string &err) {
    std::istringstream in(text);
    std::string line;
    bool sawTrace = false, inPareto = false, prevDashes = false;
    size_t cur = SIZE_MAX;

    while (std::getline(in, line)) {
        if (line.find("Trace Event Information") != std::string::npos)
            sawTrace = true;
        if (line.find("Shared Cache Line Distribution Pareto") !=
            std::string::npos) {
            inPareto = true;
            prevDashes = false;
            continue;
        }

        if (!inPareto) {
            headerValue(line, "Load Operations", out.loadOps);
            headerValue(line, "Store Operations", out.storeOps);
            headerValue(line, "Load Local HITM", out.localHitmSamples);
            headerValue(line, "Load Remote HITM", out.remoteHitmSamples);
            headerValue(line, "Total Shared Cache Lines", out.sharedLines);
            continue;
        }

        if (line.find_first_not_of(" \t\r") == std::string::npos) continue;
        if (allDashes(line)) { prevDashes = true; continue; }

        const auto t = tokens(line);
        if (t.empty()) continue;

        if (prevDashes) {
            prevDashes = false;
            if (t.size() >= 7 && isHex(t.back()) && isUInt(t[0])) {
                CoherenceLine cl;
                cl.address = toUInt(t.back());
                const size_t n = t.size();
                cl.remoteHitm = toUInt(t[1]);
                cl.localHitm = toUInt(t[2]);
                cl.storeL1Hit = toUInt(t[n - 4]);
                cl.storeL1Miss = toUInt(t[n - 3]);
                out.lines.push_back(std::move(cl));
                cur = out.lines.size() - 1;
                continue;
            }
        }

        if (cur == SIZE_MAX || !isPercent(t[0])) continue;
        CoherenceLine &cl = out.lines[cur];
        CoherenceAccess a;
        if (parseAccessRow(t, cl.localHitm, cl.remoteHitm, a))
            cl.accesses.push_back(std::move(a));
        else
            ++out.unparsedRows;
    }

    if (!sawTrace) {
        err = "not a perf c2c report: no Trace Event Information section";
        return false;
    }
    return true;
}

} // namespace lshaz
