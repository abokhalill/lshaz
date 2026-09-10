// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/event_profile.h"

#include <sstream>

namespace lshaz {

namespace {

// perf decorates symbols the linker specialised, and demangled C++ carries
// its parameter list. Neither is part of the name a finding knows.
std::string baseSymbol(const std::string &s) {
    std::string out = s;
    const auto paren = out.find('(');
    if (paren != std::string::npos) out.resize(paren);
    const auto dot = out.find('.');
    if (dot != std::string::npos) out.resize(dot);
    return out;
}

// "12.34%" to parts per million, by integer arithmetic. Two decimals is what
// perf prints; streaming through a double would put a comma in the output
// under a European locale and make two runs of one scan differ.
uint64_t percentToPPM(const std::string &tok) {
    if (tok.size() < 2 || tok.back() != '%') return 0;
    const std::string num = tok.substr(0, tok.size() - 1);
    const auto dot = num.find('.');
    uint64_t whole = 0, frac = 0;
    try {
        whole = std::stoull(dot == std::string::npos ? num : num.substr(0, dot));
        if (dot != std::string::npos) {
            std::string f = num.substr(dot + 1);
            f.resize(2, '0');
            frac = std::stoull(f);
        }
    } catch (...) {
        return 0;
    }
    return whole * 10000 + frac * 100;
}

} // namespace

bool parsePerfReport(const std::string &text, EventProfile &out,
                     std::string &err) {
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        // The map marker separates the overhead columns from the symbol and
        // is present in every layout that prints one.
        auto pos = line.find("[.]");
        if (pos == std::string::npos) pos = line.find("[k]");
        if (pos == std::string::npos) continue;

        std::istringstream head(line.substr(0, pos));
        std::string pct;
        if (!(head >> pct)) continue;
        const uint64_t ppm = percentToPPM(pct);

        std::istringstream rest(line.substr(pos + 3));
        std::string sym;
        if (!(rest >> sym) || sym.empty()) continue;

        // Several rows can resolve to one source-level name once the
        // linker's specialisation suffixes are stripped, and their shares
        // add rather than replace.
        out.bySymbol[baseSymbol(sym)] += ppm;
        out.total += ppm;
    }
    if (out.bySymbol.empty()) {
        err = "no symbols found; expected `perf report --stdio "
              "--no-children -F overhead,symbol` output";
        return false;
    }
    return true;
}

} // namespace lshaz
