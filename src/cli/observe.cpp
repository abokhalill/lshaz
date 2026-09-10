// SPDX-License-Identifier: Apache-2.0
#include "observe.h"

#include "lshaz/analysis/coherence_profile.h"
#include "lshaz/core/config.h"
#include "lshaz/core/cost.h"
#include "lshaz/core/cost_calibration.h"

#include <llvm/Support/JSON.h>
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

// Terms the profile did not measure, divided back out before a residual is
// taken.
//
// exposed_share is the model's guess at how much of a transfer the machine
// hides behind other outstanding misses. A profiler counts the transfer and
// reports its load latency; it says nothing about whether that latency was
// on the critical path. Leaving the term in would make the residual absorb
// an exposure error into a term about transfer cost.
//
// calibration is the correction a previous round already applied. Comparing
// a measurement against an already-corrected prediction and storing the
// ratio applies the correction twice, and the store would converge on
// whatever the second application happened to produce.
bool measuredByProfile(const std::string &term) {
    return term != "exposed_share" && term != "calibration";
}

// perf decorates symbols the linker specialised: dictPrefetcherRun becomes
// dictPrefetcherRun.lto_priv.0. Demangled C++ carries its parameter list.
// Neither is part of the name the analyzer knows the function by.
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
    std::string ruleID, file, mechanism, entity;
    unsigned line = 0;
    Milli reported = 0;

    // The product with only the terms a profile can see, which is what a
    // residual may be taken against.
    Milli base = 0;

    // Kept apart rather than merged into one set of names, because the claim
    // is that these two groups meet on one line. Merging them tests only
    // that some named function touched something, which on redis matched 178
    // sites for a single finding and measured the program rather than the
    // hazard.
    std::set<std::string> writers, readers;

    // basename:line of the stores. A profiler reports the DWARF line of an
    // inlined store and the symbol of whatever it was inlined into, so this
    // is the only writer-side key that survives inlining. redis stores
    // server.unixtime from a static inline the compiler folds into `call`;
    // matching on the symbol finds nothing and matching on server.c:1380 is
    // exact.
    std::set<std::string> writeSites;

    // The model already disowned this number, so no residual may be learned
    // from it.
    bool implausible = false;

    uint64_t hitmSamples = 0;
    uint64_t cycleWeight = 0;
    unsigned matchedLines = 0;
};

bool readFindings(const std::string &path, std::vector<CostedFinding> &out,
                  unsigned &uncosted, std::string &err) {
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

    for (const auto &entry : *diags) {
        const auto *d = entry.getAsObject();
        if (!d) continue;
        const auto *cost = d->getObject("cost");
        if (!cost) { ++uncosted; continue; }

        CostedFinding f;
        if (auto s = d->getString("ruleID")) f.ruleID = s->str();
        if (auto s = cost->getString("mechanism")) f.mechanism = s->str();
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
                if (!measuredByProfile(name->str())) continue;
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

void usage() {
    llvm::outs()
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
        << "  --store PATH         calibration store to read and write\n"
        << "  --write              append the observation (default: report "
           "only)\n"
        << "  --top N              unexplained lines to list (default 10)\n";
}

} // namespace

int runObserveCommand(int argc, const char **argv) {
    std::string profilePath, findingsPath, configPath, storePath;
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
        else if (a == "--machine") machineName = next("--machine");
        else if (a == "--workload") workloadName = next("--workload");
        else if (a == "--ops") ops = std::strtoull(next("--ops"), nullptr, 10);
        else if (a == "--hitm-events")
            hitmEvents = std::strtoull(next("--hitm-events"), nullptr, 10);
        else if (a == "--sample-period")
            samplePeriod = std::strtoull(next("--sample-period"), nullptr, 10);
        else if (a == "--top")
            top = static_cast<unsigned>(std::strtoul(next("--top"), nullptr, 10));
        else if (a == "--write") write = true;
        else if (a == "--help" || a == "-h") { usage(); return 0; }
        else {
            llvm::errs() << "lshaz: error: unknown option " << a << "\n";
            return 2;
        }
    }

    if (profilePath.empty() || findingsPath.empty()) {
        usage();
        return 2;
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
    if (!readFindings(findingsPath, findings, uncosted, err)) {
        llvm::errs() << "lshaz: error: " << err << "\n";
        return 3;
    }

    // The join is at line granularity because the claim is at line
    // granularity. A line-sharing finding says a writing role and a reading
    // role meet on one cache line, and a shared line in the profile is the
    // set of call sites that met on one. So a finding matches a line when
    // both of its role sets are represented there, not when either name
    // appears anywhere.
    //
    // A finding that reports at the access site rather than at a
    // declaration matches on its own file and line instead, which is the
    // route the store-rate rule takes.
    std::map<std::string, std::vector<CostedFinding *>> byName;
    for (auto &f : findings) {
        for (const auto &s : f.writers) byName[s].push_back(&f);
        for (const auto &s : f.readers) byName[s].push_back(&f);
        for (const auto &s : f.writeSites) byName[s].push_back(&f);
        byName[f.file + ":" + std::to_string(f.line)].push_back(&f);
    }

    struct Unexplained {
        uint64_t address = 0;
        uint64_t hitm = 0;
        unsigned offsets = 0;
        std::string where;
    };
    std::vector<Unexplained> unexplained;
    uint64_t measuredSamples = 0, unattributed = 0;

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
            measuredSamples += acc.hitmSamples;
            if (!worst || acc.hitmSamples > worst->hitmSamples) worst = &acc;
            if (acc.file.empty()) unattributed += acc.hitmSamples;
        }
        if (!lineHitm) continue;

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
    for (const auto &u : unexplained) unexplainedHitm += u.hitm;

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
                 << "% of measured transfers landed on a line some finding "
                    "claims\n"
                 << "  " << (measuredSamples - unexplainedHitm) << " of "
                 << measuredSamples << " attributed HITM samples\n";

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
        llvm::outs()
            << "\nNo observation stored: the profile is sampled at a scale "
               "nothing reported.\n"
               "Supply --hitm-events from a counted run, or --sample-period "
               "if the record\n"
               "used a fixed one. A sampled total scaled by a guess is not a "
               "measurement.\n";
        return 0;
    }
    if (!ops) {
        llvm::outs() << "\nNo observation stored: --ops is the operation "
                        "count the cost is per, and\nnothing supplied it.\n";
        return 0;
    }
    if (machineName.empty() || workloadName.empty()) {
        llvm::outs()
            << "\nNo observation stored: a residual is a property of the "
               "mechanism on a\nnamed machine under a named workload. Supply "
               "--machine and --workload, or\na config carrying them.\n";
        return 0;
    }

    if (byMechanism.empty()) {
        llvm::outs() << "\nNo observation stored: no costed finding joined to "
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

    if (!write) {
        llvm::outs() << "\nNot written. Rerun with --write to store, which "
                        "changes what every\nfuture scan on "
                     << machineName << "/" << workloadName << " reports.\n";
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
