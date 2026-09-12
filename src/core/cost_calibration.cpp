// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/cost_calibration.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <set>
#include <sstream>
#include <tuple>

namespace lshaz {

namespace {

// One observation per line, tab separated, integers in milli-units. A line
// format rather than a parser dependency, so a shell script can append to the
// store with printf.
//
//   mechanism \t machine \t workload \t predicted_milli \t measured_milli
//       [\t site [\t instrument]]
//
// Both trailing columns are optional, so a store written before either
// existed still reads. A row without a site measures the mechanism rather
// than a line.
bool parseLine(const std::string &line, CostObservation &out) {
    std::istringstream is(line);
    std::string pred, meas;
    if (!std::getline(is, out.mechanism, '\t')) return false;
    if (!std::getline(is, out.machine, '\t')) return false;
    if (!std::getline(is, out.workload, '\t')) return false;
    if (!std::getline(is, pred, '\t')) return false;
    if (!std::getline(is, meas, '\t')) return false;
    std::string rest;
    std::getline(is, rest);
    const auto tab = rest.find('\t');
    if (tab == std::string::npos) {
        out.site = rest;
    } else {
        out.site = rest.substr(0, tab);
        out.instrument = rest.substr(tab + 1);
    }
    try {
        out.predicted = std::stoll(pred);
        out.measured = std::stoll(meas);
    } catch (...) {
        return false;
    }
    return !out.mechanism.empty() && out.predicted > 0 && out.measured >= 0;
}

} // namespace

bool CostCalibration::load(const std::string &path, std::string &err) {
    obs_.clear();
    std::ifstream in(path);
    if (!in) {
        // Absent is empty, which is a valid state for a store nobody has fed
        // yet. Unreadable is not, and the two are distinguished by whether
        // the file exists.
        if (std::FILE *f = std::fopen(path.c_str(), "r")) {
            std::fclose(f);
            err = "cost calibration store " + path + " exists but cannot be read";
            return false;
        }
        return true;
    }
    std::string line;
    unsigned n = 0;
    while (std::getline(in, line)) {
        ++n;
        if (line.empty() || line[0] == '#') continue;
        CostObservation o;
        if (!parseLine(line, o)) {
            err = "cost calibration store " + path + ": malformed record at line " +
                  std::to_string(n);
            obs_.clear();
            return false;
        }
        obs_.push_back(std::move(o));
    }
    // Sorted on load so a store written in any order produces the same
    // corrections. The scan's output must not depend on append order.
    std::sort(obs_.begin(), obs_.end(),
              [](const CostObservation &a, const CostObservation &b) {
                  return std::tie(a.mechanism, a.machine, a.workload, a.site,
                                  a.instrument, a.predicted, a.measured) <
                         std::tie(b.mechanism, b.machine, b.workload, b.site,
                                  b.instrument, b.predicted, b.measured);
              });
    return true;
}

bool CostCalibration::save(const std::string &path, std::string &err) const {
    const std::string tmp = path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "cannot write " + tmp;
            return false;
        }
        out << "# mechanism\tmachine\tworkload\tpredicted_milli"
               "\tmeasured_milli\tsite\tinstrument\n";
        for (const auto &o : obs_)
            out << o.mechanism << '\t' << o.machine << '\t' << o.workload
                << '\t' << o.predicted << '\t' << o.measured << '\t'
                << o.site << '\t' << o.instrument << '\n';
        if (!out) {
            err = "write failed for " + tmp;
            return false;
        }
    }
    if (std::rename(tmp.c_str(), path.c_str()) != 0) {
        err = "cannot replace " + path;
        return false;
    }
    return true;
}

void CostCalibration::observe(const CostObservation &o) { obs_.push_back(o); }

std::optional<CostCalibration::Factor>
CostCalibration::factorFor(const std::string &mechanism,
                           const std::string &machine,
                           const std::string &workload,
                           const std::string &site,
                           const std::string &instrument) const {
    std::set<std::string> seen;
    const auto gather = [&](bool wantSite) {
        std::vector<Milli> out;
        seen.clear();
        for (const auto &o : obs_) {
            if (o.mechanism != mechanism || o.machine != machine ||
                o.workload != workload || o.predicted <= 0)
                continue;
            if (wantSite ? o.site != site : !o.site.empty())
                continue;
            if (!instrument.empty() && o.instrument != instrument)
                continue;
            seen.insert(o.instrument);
            out.push_back(static_cast<Milli>(
                (static_cast<__int128>(o.measured) * kMilli) / o.predicted));
        }
        return out;
    };

    // This line's own measurements first. Falling back to the mechanism's
    // median is what every unmeasured line gets, and mixing the two would
    // pull a measured site back toward the average of lines that are not it.
    bool sited = false;
    std::vector<Milli> ratios;
    if (!site.empty()) {
        ratios = gather(/*wantSite=*/true);
        sited = !ratios.empty();
    }
    if (ratios.empty())
        ratios = gather(/*wantSite=*/false);
    if (ratios.empty())
        return std::nullopt;
    std::sort(ratios.begin(), ratios.end());
    Factor f;
    f.sited = sited;
    f.mixedInstruments = seen.size() > 1;
    f.samples = static_cast<unsigned>(ratios.size());
    const size_t mid = ratios.size() / 2;
    // Even counts average the two central values, which keeps the result an
    // exact integer and independent of which of the pair came first.
    f.value = ratios.size() % 2 ? ratios[mid]
                                : (ratios[mid - 1] + ratios[mid]) / 2;
    return f;
}

} // namespace lshaz
