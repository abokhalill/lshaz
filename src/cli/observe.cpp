// SPDX-License-Identifier: Apache-2.0
#include "observe.h"

#include "lshaz/analysis/coherence_profile.h"
#include "lshaz/analysis/event_profile.h"
#include "lshaz/core/config.h"
#include "lshaz/core/evidence.h"
#include "lshaz/core/cost.h"
#include "lshaz/core/cost_calibration.h"

#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <cstring>
#include <map>
#include <sstream>
#include <set>
#include <string>
#include <vector>

namespace lshaz {

namespace {

// A profile counts events, so the residual is taken against the event-rate
// product. Conversion terms turn events into exposed cycles and a counter
// never saw that; corrections are last round's answer and measuring against
// one applies it twice.
//
// Keyed on the declared role rather than the term's name: the estimate and
// this comparison live in different files, and a renamed term must not
// silently change which quantity the machine is being asked about.
bool measuredByProfile(llvm::StringRef role) {
    return role.empty() || role == "event_rate";
}

// dictPrefetcherRun arrives as dictPrefetcherRun.lto_priv.0, and demangled
// C++ drags its parameter list along. Neither is the name we know it by.
std::string baseSymbol(const std::string &s) {
    std::string out = s;
    const auto paren = out.find('(');
    if (paren != std::string::npos) out.resize(paren);
    const auto dot = out.find('.');
    if (dot != std::string::npos) out.resize(dot);
    return out;
}

std::string basename(const std::string &p) {
    const auto slash = p.find_last_of('/');
    return slash == std::string::npos ? p : p.substr(slash + 1);
}

struct CostedFinding {
    std::string ruleID, file, mechanism, entity, site;
    unsigned line = 0;
    Milli reported = 0;

    // Only the terms a profile can see. Residuals go against this.
    Milli base = 0;

    // Two sets, not one. The claim is that these groups meet on a line;
    // merged, it only tests that some named function touched something, which
    // matches most of the program for any widely-accessed record.
    std::set<std::string> writers, readers;

    // basename:line of the stores, the only writer-side key that survives
    // inlining: a profiler reports a static-inline writer under whatever
    // symbol it was inlined into, but its DWARF line is exact.
    std::set<std::string> writeSites;

    // The model disowned this number, so we can't learn from it.
    bool implausible = false;

    uint64_t hitmSamples = 0;
    uint64_t cycleWeight = 0;
    unsigned matchedLines = 0;
};

// Every finding with the symbols it accuses, costed or not.
//
// The cost model only reaches coherence, so a branch or TLB rule produces no
// estimate and was invisible to every measurement we take. That is how seven
// of eight families went unchecked.
struct RuleSite {
    std::string ruleID;
    std::string entity;
    std::set<std::string> symbols;
};

bool readFindings(const std::string &path, std::vector<CostedFinding> &out,
                  std::vector<RuleSite> &sites, unsigned &uncosted,
                  std::string &err) {
    auto buf = llvm::MemoryBuffer::getFile(path);
    if (!buf) {
        err = "cannot read " + path + ": " + buf.getError().message();
        return false;
    }
    auto parsed = llvm::json::parse(buf.get()->getBuffer());
    if (!parsed) {
        err = "cannot parse " + path + " as JSON";
        return false;
    }
    const auto *root = parsed->getAsObject();
    if (!root) {
        err = path + " is not a JSON object";
        return false;
    }
    const auto *diags = root->getArray("diagnostics");
    if (!diags) {
        err = path + " has no diagnostics array";
        return false;
    }

    const auto splitInto = [](const std::string &names,
                              std::set<std::string> &into) {
        size_t start = 0;
        while (start <= names.size()) {
            const auto comma = names.find(',', start);
            const auto end = comma == std::string::npos ? names.size() : comma;
            if (end > start) into.insert(names.substr(start, end - start));
            if (comma == std::string::npos) break;
            start = comma + 1;
        }
    };

    for (const auto &entry : *diags) {
        const auto *d = entry.getAsObject();
        if (!d) continue;

        // The symbol view, taken for every finding whether or not the cost
        // model reached it.
        RuleSite rs;
        if (auto s = d->getString("ruleID")) rs.ruleID = s->str();
        if (auto s = d->getString("functionName"))
            if (!s->empty()) rs.symbols.insert(s->str());
        if (const auto *se = d->getObject("structuralEvidence")) {
            if (auto s = se->getString("type_name")) rs.entity = s->str();
            if (auto s = se->getString("field")) rs.entity += "::" + s->str();
            if (auto s = se->getString("cost_writers"))
                splitInto(s->str(), rs.symbols);
            if (auto s = se->getString("cost_readers"))
                splitInto(s->str(), rs.symbols);
            if (auto s = se->getString("access_symbols"))
                splitInto(s->str(), rs.symbols);
        }
        if (const auto *loc = d->getObject("location"))
            if (rs.entity.empty())
                if (auto s = loc->getString("file"))
                    rs.entity = basename(s->str());
        if (!rs.ruleID.empty() && !rs.symbols.empty())
            sites.push_back(std::move(rs));

        const auto *cost = d->getObject("cost");
        if (!cost) { ++uncosted; continue; }

        CostedFinding f;
        if (auto s = d->getString("ruleID")) f.ruleID = s->str();
        if (auto s = cost->getString("mechanism")) f.mechanism = s->str();
        if (auto s = cost->getString("site")) f.site = s->str();
        if (const auto *loc = d->getObject("location")) {
            if (auto s = loc->getString("file")) f.file = basename(s->str());
            if (auto n = loc->getInteger("line"))
                f.line = static_cast<unsigned>(*n);
        }
        if (const auto *se = d->getObject("structuralEvidence")) {
            if (auto s = se->getString("type_name")) f.entity = s->str();
            // A record has many fields and several may sit on one line, so
            // the type alone names two different claims identically.
            if (auto s = se->getString("field"))
                f.entity += "::" + s->str();
            if (auto s = se->getString("cost_implausible"))
                f.implausible = s->str() == "yes";
            const auto split = [](const std::string &names,
                                  std::set<std::string> &into) {
                size_t start = 0;
                while (start <= names.size()) {
                    const auto comma = names.find(',', start);
                    const auto end =
                        comma == std::string::npos ? names.size() : comma;
                    if (end > start)
                        into.insert(names.substr(start, end - start));
                    if (comma == std::string::npos) break;
                    start = comma + 1;
                }
            };
            if (auto s = se->getString("cost_writers")) split(s->str(), f.writers);
            if (auto s = se->getString("cost_readers")) split(s->str(), f.readers);
            if (auto s = se->getString("cost_write_sites"))
                split(s->str(), f.writeSites);
        }
        if (f.entity.empty()) f.entity = f.file + ":" + std::to_string(f.line);

        // cyclesPerOp ships as decimal cycles; the store works in milli.
        if (auto v = cost->getNumber("cyclesPerOp"))
            f.reported = static_cast<Milli>(*v * kMilli + 0.5);

        Milli base = kMilli;
        bool anyTerm = false;
        if (const auto *terms = cost->getArray("terms")) {
            for (const auto &te : *terms) {
                const auto *t = te.getAsObject();
                if (!t) continue;
                auto name = t->getString("name");
                auto val = t->getNumber("value");
                if (!name || !val) continue;
                if (!measuredByProfile(t->getString("role").value_or("")))
                    continue;
                base = milliMul(base,
                                static_cast<Milli>(*val * kMilli + 0.5));
                anyTerm = true;
            }
        }
        f.base = anyTerm ? base : 0;
        out.push_back(std::move(f));
    }
    return true;
}

// What the machine actually ran, from `perf report --stdio`.
//
// Recall is a metric you win by reporting more, so it needs the other half.
// The precision denominator isn't every finding: a hazard on a path the
// workload never took is untested, not wrong.
std::set<std::string> parseExecutedSymbols(const std::string &text) {
    std::set<std::string> out;
    std::istringstream in(text);
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#') continue;
        // The map marker separates the overhead columns from the symbol,
        // and is present in every perf report layout that prints one.
        const auto mark = line.find("[.]");
        const auto pos = mark == std::string::npos ? line.find("[k]") : mark;
        if (pos == std::string::npos) continue;
        std::istringstream rest(line.substr(pos + 3));
        std::string sym;
        if (rest >> sym && !sym.empty())
            out.insert(baseSymbol(sym));
    }
    return out;
}

// Explicit --help is a success and belongs on stdout; every other route here
// is a bad invocation and belongs on stderr.
void usage(bool asError = true) {
    llvm::raw_ostream &o = asError ? llvm::errs() : llvm::outs();
    o
        << "Usage: lshaz observe --profile <c2c.txt> --findings <scan.json> "
           "[options]\n\n"
        << "Feeds a hardware profile back into the cost model. Findings are\n"
        << "joined to measured coherence traffic by the call sites the cost\n"
        << "was built from, and the residual is stored against the mechanism\n"
        << "so it corrects every future scan that composes the same terms.\n\n"
        << "Required for a stored observation:\n"
        << "  --ops N              operations the target completed in the "
           "profiled window\n"
        << "  --hitm-events N      counted coherence transfers in the same "
           "window, or\n"
        << "  --sample-period N    the record's fixed sample period, if it "
           "used one\n\n"
        << "Without one of those the profile is sampled at an unknown scale "
           "and only\n"
        << "the ranking is reported. A profile is never scaled by a guess.\n\n"
        << "Options:\n"
        << "  --config PATH        read machine, workload and store path from "
           "a config\n"
        << "  --machine NAME       machine key, overriding the config\n"
        << "  --workload NAME      workload key, overriding the config\n"
        << "  --executed PATH      `perf report --stdio` from the same "
           "window, which\n"
        << "                       turns recall into a pair by naming what "
           "ran\n"
        << "  --object NAME        the binary that was analyzed. Recall is "
           "scoped to it,\n"
        << "                       and it is inferred and printed if absent\n"
        << "  --store PATH         calibration store to read and write\n"
        << "  --write              append the observation (default: report "
           "only)\n"
        << "  --top N              unexplained lines to list (default 10)\n";
}

} // namespace

int runObserveCommand(int argc, const char **argv) {
    std::string profilePath, findingsPath, configPath, storePath, executedPath,
        targetObject;
    std::vector<std::pair<std::string, std::string>> evidenceArgs;
    std::string machineName, workloadName;
    uint64_t ops = 0, hitmEvents = 0, samplePeriod = 0;
    unsigned top = 10;
    bool write = false;

    for (int i = 0; i < argc; ++i) {
        const std::string a = argv[i];
        const auto next = [&](const char *what) -> const char * {
            if (i + 1 >= argc) {
                llvm::errs() << "lshaz: error: " << what << " needs a value\n";
                std::exit(2);
            }
            return argv[++i];
        };
        if (a == "--profile") profilePath = next("--profile");
        else if (a == "--findings") findingsPath = next("--findings");
        else if (a == "--config") configPath = next("--config");
        else if (a == "--store") storePath = next("--store");
        else if (a == "--executed") executedPath = next("--executed");
        else if (a == "--object") targetObject = next("--object");
        else if (a == "--evidence") {
            const std::string spec = next("--evidence");
            const auto eq = spec.find('=');
            if (eq == std::string::npos) {
                llvm::errs() << "lshaz: error: --evidence wants "
                                "family=path, got " << spec << "\n";
                return 3;
            }
            evidenceArgs.emplace_back(spec.substr(0, eq), spec.substr(eq + 1));
        }
        else if (a == "--machine" || a == "--machine-name")
            machineName = next(a.c_str());
        else if (a == "--workload") workloadName = next("--workload");
        else if (a == "--ops") ops = std::strtoull(next("--ops"), nullptr, 10);
        else if (a == "--hitm-events")
            hitmEvents = std::strtoull(next("--hitm-events"), nullptr, 10);
        else if (a == "--sample-period")
            samplePeriod = std::strtoull(next("--sample-period"), nullptr, 10);
        else if (a == "--top")
            top = static_cast<unsigned>(std::strtoul(next("--top"), nullptr, 10));
        else if (a == "--write") write = true;
        else if (a == "--help" || a == "-h") { usage(/*asError=*/false); return 0; }
        else {
            llvm::errs() << "lshaz: error: unknown option " << a << "\n";
            return 3;
        }
    }

    if (profilePath.empty() || findingsPath.empty()) {
        usage();
        return 3;
    }

    Config cfg = configPath.empty() ? Config::defaults()
                                    : Config::loadFromFile(configPath);
    if (machineName.empty()) machineName = cfg.machineName;
    if (workloadName.empty()) workloadName = cfg.workloadName;
    if (storePath.empty()) storePath = cfg.costCalibrationPath;

    auto profileBuf = llvm::MemoryBuffer::getFile(profilePath);
    if (!profileBuf) {
        llvm::errs() << "lshaz: error: cannot read " << profilePath << ": "
                     << profileBuf.getError().message() << "\n";
        return 3;
    }
    CoherenceProfile prof;
    std::string err;
    if (!parsePerfC2CReport(profileBuf.get()->getBuffer().str(), prof, err)) {
        llvm::errs() << "lshaz: error: " << err << "\n";
        return 3;
    }
    prof.origin = profilePath;

    std::vector<CostedFinding> findings;
    unsigned uncosted = 0;
    std::vector<RuleSite> sites;
    if (!readFindings(findingsPath, findings, sites, uncosted, err)) {
        llvm::errs() << "lshaz: error: " << err << "\n";
        return 3;
    }

    // Join at line granularity, because the claim is at line granularity: a
    // sharing finding says a writing role and a reading role meet on one
    // line, so both role sets have to appear there, not just either name.
    // Rules reporting at the access site match on their own file and line.
    std::map<std::string, std::vector<CostedFinding *>> byName;
    for (auto &f : findings) {
        for (const auto &s : f.writers) byName[s].push_back(&f);
        for (const auto &s : f.readers) byName[s].push_back(&f);
        for (const auto &s : f.writeSites) byName[s].push_back(&f);
        byName[f.file + ":" + std::to_string(f.line)].push_back(&f);
    }

    // Which binary we were pointed at. Traffic inside a dependency is not our
    // miss: a scan of the project's own sources never names a lock inside
    // libc, and a single hot allocator line can carry most of a run's
    // transfers.
    //
    // Vote by distinct lines rather than samples, so one enormous dependency
    // line cannot win. Printed and overridable: it decides a headline
    // number.
    std::map<std::string, unsigned> objectLines;
    for (const auto &line : prof.lines) {
        std::set<std::string> here;
        for (const auto &acc : line.accesses)
            if (!acc.object.empty()) here.insert(acc.object);
        for (const auto &o : here) ++objectLines[o];
    }
    std::string target = targetObject;
    if (target.empty()) {
        unsigned best = 0;
        for (const auto &[obj, n] : objectLines)
            if (n > best) { best = n; target = obj; }
    }

    struct Unexplained {
        uint64_t address = 0;
        uint64_t hitm = 0;
        unsigned offsets = 0;
        std::string where;
        bool inTarget = true;
    };
    std::vector<Unexplained> unexplained;
    uint64_t measuredSamples = 0, unattributed = 0, dependencySamples = 0;

    // Lines whose code the machine ran and which produced no coherence
    // traffic at all. A measurement of zero is a measurement, and recording
    // it is how the loop that closed the ranking gap closes the precision
    // gap: the next scan prices these at what they were observed to cost.
    std::vector<const CostedFinding *> executedSilent;

    // Measured traffic per mechanism, counted once per line however many
    // findings claim it. Summing per finding instead would count one
    // transfer as many times as the analyzer happened to report it.
    struct Bucket {
        Milli predicted = 0;
        uint64_t samples = 0;
        uint64_t cycleWeight = 0;
        unsigned findings = 0;
        unsigned lines = 0;
    };
    std::map<std::string, Bucket> byMechanism;

    for (const auto &line : prof.lines) {
        uint64_t lineHitm = 0, lineCycleWeight = 0;
        const CoherenceAccess *worst = nullptr;
        std::set<std::string> names;
        for (const auto &acc : line.accesses) {
            // Every access names the line, whether or not it took a HITM.
            // The storing side of a contended line does not appear as a
            // load-HITM at all: it appears as a store, and the transfers it
            // causes are booked against the readers. Restricting the name
            // set to HITM-carrying rows hid every writer on every line,
            // which is precisely the half a sharing finding needs matched.
            names.insert(baseSymbol(acc.symbol));
            if (!acc.file.empty())
                names.insert(acc.file + ":" + std::to_string(acc.line));

            if (!acc.hitmSamples) continue;
            lineHitm += acc.hitmSamples;
            lineCycleWeight += acc.hitmSamples * acc.hitmCycles;
            if (!worst || acc.hitmSamples > worst->hitmSamples) worst = &acc;
            if (acc.file.empty()) unattributed += acc.hitmSamples;
        }
        if (!lineHitm) continue;

        // A line the analyzer was never shown. Counted and reported, never
        // silently dropped: a target whose contention has moved into its
        // allocator is a real result about the target.
        const bool inTarget = !worst || worst->object.empty() ||
                              target.empty() || worst->object == target;
        if (!inTarget) {
            dependencySamples += lineHitm;
            Unexplained u;
            u.address = line.address;
            u.hitm = lineHitm;
            u.offsets = line.contendedOffsets();
            u.inTarget = false;
            u.where = worst ? worst->symbol + " in " + worst->object
                            : std::string("unresolved");
            unexplained.push_back(std::move(u));
            continue;
        }
        measuredSamples += lineHitm;

        std::set<CostedFinding *> candidates;
        for (const auto &n : names) {
            auto it = byName.find(n);
            if (it != byName.end())
                candidates.insert(it->second.begin(), it->second.end());
        }

        std::set<std::string> mechanismsHere;
        bool anyMatch = false;
        for (auto *f : candidates) {
            const bool loc =
                names.count(f->file + ":" + std::to_string(f->line)) > 0;
            const auto present = [&](const std::set<std::string> &role) {
                for (const auto &r : role)
                    if (names.count(r)) return true;
                return false;
            };
            const bool w = present(f->writers) || present(f->writeSites);
            const bool r = present(f->readers);
            const bool both = f->writers.empty()   ? r
                              : f->readers.empty() ? w
                                                   : (w && r);
            if (!loc && !both) continue;
            anyMatch = true;
            f->hitmSamples += lineHitm;
            f->cycleWeight += lineCycleWeight;
            ++f->matchedLines;
            if (!f->implausible && f->base > 0 && !f->mechanism.empty())
                mechanismsHere.insert(f->mechanism);
        }
        for (const auto &m : mechanismsHere) {
            auto &b = byMechanism[m];
            b.samples += lineHitm;
            b.cycleWeight += lineCycleWeight;
            ++b.lines;
        }

        if (!anyMatch) {
            Unexplained u;
            u.address = line.address;
            u.hitm = lineHitm;
            u.offsets = line.contendedOffsets();
            if (worst) {
                u.where = worst->symbol;
                if (!worst->file.empty())
                    u.where += " (" + worst->file + ":" +
                               std::to_string(worst->line) + ")";
            }
            unexplained.push_back(std::move(u));
        }
    }

    for (const auto &f : findings) {
        if (!f.hitmSamples || f.implausible || f.base <= 0 ||
            f.mechanism.empty())
            continue;
        auto it = byMechanism.find(f.mechanism);
        if (it == byMechanism.end()) continue;
        it->second.predicted += f.base;
        ++it->second.findings;
    }

    llvm::outs() << "Profile: " << prof.origin << "\n"
                 << "  shared lines            " << prof.lines.size()
                 << " (report header says " << prof.sharedLines << ")\n"
                 << "  HITM samples            " << prof.totalHitmSamples()
                 << " local " << prof.localHitmSamples << ", remote "
                 << prof.remoteHitmSamples << "\n"
                 << "  attributed to a line    " << measuredSamples << "\n"
                 << "  no source line          " << unattributed << "\n"
                 << "  unreadable rows         " << prof.unparsedRows << "\n";
    if (unsigned mhc = prof.meanHitmCycles())
        llvm::outs() << "  measured HITM latency   " << mhc
                     << " cycles, sample-weighted\n";
    else
        llvm::outs() << "  measured HITM latency   none: no HITM sample "
                        "carried a latency\n";

    llvm::outs() << "\nFindings: " << findingsPath << "\n"
                 << "  costed                  " << findings.size() << "\n"
                 << "  uncosted, skipped       " << uncosted << "\n";

    // A transfer's marginal cost is its measured latency less what the load
    // would have cost had the line stayed put, and the line was in this
    // core's cache until another core took it.
    const unsigned l1Cycles = MachineModel{}.cyclesL1;

    uint64_t scaleNum = 0;
    const char *scaleFrom = nullptr;
    if (hitmEvents) {
        scaleNum = hitmEvents;
        scaleFrom = "counted events";
    } else if (samplePeriod && prof.totalHitmSamples()) {
        scaleNum = prof.totalHitmSamples() * samplePeriod;
        scaleFrom = "fixed sample period";
    }

    std::sort(findings.begin(), findings.end(),
              [](const CostedFinding &a, const CostedFinding &b) {
                  if (a.hitmSamples != b.hitmSamples)
                      return a.hitmSamples > b.hitmSamples;
                  return a.entity < b.entity;
              });

    unsigned joinedFindings = 0;
    for (const auto &f : findings)
        if (f.hitmSamples) ++joinedFindings;
    llvm::outs() << "  joined to measurement   " << joinedFindings << "\n"
                 << "  predicted, unmeasured   "
                 << (findings.size() - joinedFindings) << "\n";

    if (joinedFindings) {
        llvm::outs() << "\nJoined, by measured traffic:\n";
        for (const auto &f : findings) {
            if (!f.hitmSamples) continue;
            const unsigned lat = static_cast<unsigned>(
                (f.cycleWeight + f.hitmSamples / 2) / f.hitmSamples);
            llvm::outs()
                << "  " << f.ruleID << "  " << f.entity << "\n"
                << "      predicted " << milliToText(f.reported)
                << " cycles/op, measurable part " << milliToText(f.base)
                << "\n"
                << "      measured  " << f.hitmSamples << " HITM samples at "
                << lat << " cycles across " << f.matchedLines
                << " shared line(s)" << (f.implausible ? ", implausible" : "")
                << "\n";
        }
    }

    // Findings the model priced and the machine never touched. Not a
    // refutation on its own: the window may not have exercised the path.
    // Named anyway, because a prediction nobody can find is the shape a
    // wrong term takes.
    unsigned silent = 0;
    for (const auto &f : findings)
        if (!f.hitmSamples && ++silent <= top) {
            if (silent == 1)
                llvm::outs() << "\nPredicted, not observed in this window:\n";
            llvm::outs() << "  " << f.ruleID << "  " << f.entity
                         << "  predicted " << milliToText(f.reported)
                         << " cycles/op\n";
        }

    // The other direction, and the more interesting one. Every line here is
    // coherence traffic the machine paid for and no rule named.
    std::sort(unexplained.begin(), unexplained.end(),
              [](const Unexplained &a, const Unexplained &b) {
                  if (a.hitm != b.hitm) return a.hitm > b.hitm;
                  return a.address < b.address;
              });
    uint64_t unexplainedHitm = 0;
    for (const auto &u : unexplained)
        if (u.inTarget) unexplainedHitm += u.hitm;

    // The number this whole path exists to produce. A static analyzer's
    // recall against the hardware, on a named machine under a named
    // workload, is measurable rather than arguable, and it is the only
    // honest way to say whether the next rule is worth having.
    llvm::outs() << "\nCoherence recall on " << machineName << "/"
                 << workloadName << ": "
                 << (measuredSamples
                         ? (measuredSamples - unexplainedHitm) * 100 /
                               measuredSamples
                         : 0)
                 << "% of transfers measured in " + target +
                        " landed on a line some finding claims\n"
                 << "  " << (measuredSamples - unexplainedHitm) << " of "
                 << measuredSamples << " attributed HITM samples\n";
    if (dependencySamples)
        llvm::outs() << "  " << dependencySamples
                     << " more landed in a dependency, not counted either "
                        "way\n";

    // The other half. Recall is a metric you can win by reporting
    // everything, so on its own it flatters whoever built it.
    if (!executedPath.empty()) {
        auto execBuf = llvm::MemoryBuffer::getFile(executedPath);
        if (!execBuf) {
            llvm::errs() << "lshaz: error: cannot read " << executedPath
                         << ": " << execBuf.getError().message() << "\n";
            return 3;
        }
        const auto executed =
            parseExecutedSymbols(execBuf.get()->getBuffer().str());
        if (executed.empty()) {
            llvm::errs() << "lshaz: error: no symbols in " << executedPath
                         << "; expected `perf report --stdio` output\n";
            return 3;
        }

        unsigned ran = 0, confirmed = 0;
        executedSilent.clear();
        std::vector<const CostedFinding *> silent;
        for (const auto &f : findings) {
            bool executedHere = false;
            for (const auto &s : f.writers)
                if (executed.count(s)) { executedHere = true; break; }
            for (const auto &s : f.readers) {
                if (executedHere) break;
                if (executed.count(s)) executedHere = true;
            }
            if (!executedHere) continue;
            ++ran;
            if (f.hitmSamples) {
                ++confirmed;
            } else {
                silent.push_back(&f);
                if (!f.site.empty() && !f.implausible && f.base > 0)
                    executedSilent.push_back(&f);
            }
        }

        llvm::outs() << "\nCoherence precision on " << machineName << "/"
                     << workloadName << ": "
                     << (ran ? confirmed * 100 / ran : 0)
                     << "% of findings whose code ran showed measured "
                        "traffic\n"
                     << "  " << confirmed << " of " << ran
                     << " costed findings, from " << executed.size()
                     << " executed symbol(s)\n"
                     << "  " << (findings.size() - ran)
                     << " excluded, their code never ran here\n";

        if (!silent.empty()) {
            llvm::outs() << "\nRan, stayed silent (" << silent.size()
                         << "):\n";
            std::sort(silent.begin(), silent.end(),
                      [](const CostedFinding *a, const CostedFinding *b) {
                          if (a->reported != b->reported)
                              return a->reported > b->reported;
                          return a->entity < b->entity;
                      });
            for (unsigned i = 0; i < silent.size() && i < top; ++i)
                llvm::outs() << "  " << silent[i]->ruleID << "  "
                             << silent[i]->entity << "  predicted "
                             << milliToText(silent[i]->reported)
                             << " cycles/op\n";
        }
    }

    // Every other mechanism the rule set claims. Coherence has the c2c path
    // above, which locates a line as well as a symbol; the rest have only a
    // per-symbol event count, which is enough to ask the one question that
    // matters: the code ran, so did the effect it was accused of happen
    // there or not.
    if (!evidenceArgs.empty()) {
        if (executedPath.empty()) {
            llvm::errs() << "lshaz: error: --evidence needs --executed. "
                            "A symbol carrying no branch misses proves "
                            "nothing\n  unless something else says it ran.\n";
            return 2;
        }
        auto execBuf = llvm::MemoryBuffer::getFile(executedPath);
        EventProfile ranProfile;
        if (!execBuf ||
            !parsePerfReport(execBuf.get()->getBuffer().str(), ranProfile,
                             err)) {
            llvm::errs() << "lshaz: error: " << executedPath << ": "
                         << (execBuf ? err : execBuf.getError().message())
                         << "\n";
            return 3;
        }

        llvm::outs() << "\nPer-mechanism confirmation, against what the "
                        "machine counted:\n";
        for (const auto &[familyName, path] : evidenceArgs) {
            const auto family = evidenceFamilyFromName(familyName);
            if (family == EvidenceFamily::None) {
                llvm::errs() << "lshaz: error: unknown evidence family '"
                             << familyName << "'\n";
                return 2;
            }
            auto buf = llvm::MemoryBuffer::getFile(path);
            EventProfile ev;
            ev.event = familyName;
            if (!buf ||
                !parsePerfReport(buf.get()->getBuffer().str(), ev, err)) {
                llvm::errs() << "lshaz: error: " << path << ": "
                             << (buf ? err : buf.getError().message()) << "\n";
                return 3;
            }

            std::map<std::string, std::pair<unsigned, unsigned>> perRule;
            std::vector<const RuleSite *> refuted;
            unsigned ran = 0, confirmed = 0, unlocalised = 0;
            for (const auto &s : sites) {
                const auto *rule = evidenceForRule(s.ruleID);
                if (!rule || rule->family != family) continue;
                bool executedHere = false, sawEvent = false;
                for (const auto &sym : s.symbols) {
                    if (ranProfile.ran(sym)) executedHere = true;
                    if (ev.ran(sym)) sawEvent = true;
                }
                if (!executedHere) continue;
                // The cost of an allocation is paid inside the allocator,
                // not in the function that called it, so a silent caller is
                // not a refutation and must not be counted as one.
                if (!rule->localised) { ++unlocalised; continue; }
                ++ran;
                auto &tally = perRule[s.ruleID];
                ++tally.second;
                if (sawEvent) { ++confirmed; ++tally.first; }
                else refuted.push_back(&s);
            }

            llvm::outs() << "  " << familyName << ": ";
            if (!ran && !unlocalised) {
                llvm::outs() << "no finding of this family had code that ran "
                                "in this window\n";
                continue;
            }
            if (ran)
                llvm::outs() << confirmed * 100 / ran << "% confirmed, "
                             << confirmed << " of " << ran
                             << " finding(s) whose code ran\n";
            else
                llvm::outs() << "nothing to confirm\n";
            for (const auto &[rule, tally] : perRule)
                llvm::outs() << "      " << rule << "  " << tally.first
                             << "/" << tally.second << "\n";
            if (unlocalised)
                llvm::outs()
                    << "      " << unlocalised
                    << " finding(s) not judged: their cost is paid somewhere "
                       "other than\n      the code that caused it, so a "
                       "silent symbol refutes nothing\n";
            for (unsigned i = 0; i < refuted.size() && i < top; ++i)
                llvm::outs() << "      ran without the effect: "
                             << refuted[i]->ruleID << "  "
                             << refuted[i]->entity << "\n";
        }
    }


    if (!unexplained.empty()) {
        llvm::outs() << "\nMeasured, unexplained by any finding ("
                     << unexplained.size() << " lines, " << unexplainedHitm
                     << " HITM samples):\n";
        for (unsigned i = 0; i < unexplained.size() && i < top; ++i) {
            const auto &u = unexplained[i];
            llvm::outs() << "  " << u.hitm << " HITM  " << u.offsets
                         << " contended offset(s)  " << u.where << "\n";
        }
    }

    if (!scaleFrom) {
        llvm::outs() << "\nNothing stored: the profile is sampled and nothing "
                        "gave the scale.\n"
                        "Pass --hitm-events from a counted run, or "
                        "--sample-period if the record used one.\n";
        return 0;
    }
    if (!ops) {
        llvm::outs() << "\nNothing stored: --ops is what the cost is per.\n";
        return 0;
    }
    if (machineName.empty() || workloadName.empty()) {
        llvm::outs() << "\nNothing stored: a residual needs a named machine "
                        "and workload.\nPass --machine and --workload, or a "
                        "config carrying them.\n";
        return 0;
    }

    if (byMechanism.empty()) {
        llvm::outs() << "\nNothing stored: no costed finding joined to "
                        "measured traffic.\n";
        return 0;
    }

    CostCalibration store;
    if (!storePath.empty() && !store.load(storePath, err)) {
        llvm::errs() << "lshaz: error: " << err << "\n";
        return 3;
    }

    llvm::outs() << "\nObservations (" << scaleFrom << ", " << scaleNum
                 << " events over " << ops << " operations):\n";
    for (const auto &[mech, b] : byMechanism) {
        const unsigned latency = static_cast<unsigned>(
            (b.cycleWeight + b.samples / 2) / b.samples);
        const unsigned marginal = latency > l1Cycles ? latency - l1Cycles : 0;
        const uint64_t total = prof.totalHitmSamples();
        if (!total) continue;
        const Milli measured = static_cast<Milli>(
            (static_cast<__int128>(b.samples) * scaleNum * marginal * kMilli) /
            (static_cast<__int128>(total) * ops));

        llvm::outs() << "  " << mech << " on " << machineName << "/"
                     << workloadName << "\n"
                     << "      from " << b.findings << " finding(s), "
                     << b.samples << " of " << total << " HITM samples\n"
                     << "      predicted " << milliToText(b.predicted)
                     << " cycles/op, measured " << milliToText(measured)
                     << " cycles/op at " << marginal << " marginal cycles\n";
        if (b.predicted > 0) {
            const Milli ratio = static_cast<Milli>(
                (static_cast<__int128>(measured) * kMilli) / b.predicted);
            llvm::outs() << "      residual  x" << milliToText(ratio) << "\n";
        }

        CostObservation o;
        o.mechanism = mech;
        o.machine = machineName;
        o.workload = workloadName;
        o.predicted = b.predicted;
        o.measured = measured;
        store.observe(o);
    }

    // One row per measured line as well as one per mechanism. The sited rows
    // are the half that ranks: the static model prices two lines identically
    // whenever both are stored on the same path, correctly, because reads do
    // not multiply transfers and how often each is stored per operation is a
    // property of the run.
    unsigned sited = 0;
    const uint64_t total = prof.totalHitmSamples();
    for (const auto &f : findings) {
        if (!f.hitmSamples || f.implausible || f.base <= 0 ||
            f.mechanism.empty() || f.site.empty() || !total)
            continue;
        const unsigned latency = static_cast<unsigned>(
            (f.cycleWeight + f.hitmSamples / 2) / f.hitmSamples);
        const unsigned marginal = latency > l1Cycles ? latency - l1Cycles : 0;
        CostObservation o;
        o.mechanism = f.mechanism;
        o.machine = machineName;
        o.workload = workloadName;
        o.site = f.site;
        o.predicted = f.base;
        o.measured = static_cast<Milli>(
            (static_cast<__int128>(f.hitmSamples) * scaleNum * marginal *
             kMilli) /
            (static_cast<__int128>(total) * ops));
        store.observe(o);
        if (sited++ < top)
            llvm::outs() << "  " << f.site << " (" << f.mechanism
                         << "): predicted " << milliToText(f.base)
                         << ", measured " << milliToText(o.measured)
                         << " cycles/op from " << f.hitmSamples
                         << " sample(s)\n";
    }
    // Zero is a measurement. Without these the store only ever learns about
    // lines that cost something, so a line the machine has repeatedly shown
    // silent is reported at the same grade every scan.
    unsigned zeroed = 0;
    for (const auto *f : executedSilent) {
        CostObservation o;
        o.mechanism = f->mechanism;
        o.machine = machineName;
        o.workload = workloadName;
        o.site = f->site;
        o.predicted = f->base;
        o.measured = 0;
        store.observe(o);
        ++zeroed;
    }
    if (sited || zeroed)
        llvm::outs() << "  " << sited << " line(s) measured, " << zeroed
                     << " ran silent\n";

    if (!write) {
        llvm::outs() << "\nNot written. --write stores these, which changes "
                        "what every future scan\non " << machineName << "/"
                     << workloadName << " reports.\n";
        return 0;
    }
    if (storePath.empty()) {
        llvm::errs() << "lshaz: error: --write needs --store or a config with "
                        "cost_calibration_path\n";
        return 2;
    }
    if (!store.save(storePath, err)) {
        llvm::errs() << "lshaz: error: " << err << "\n";
        return 3;
    }
    llvm::outs() << "\nStored in " << storePath << ", now " << store.size()
                 << " observation(s).\n";
    return 0;
}

} // namespace lshaz
