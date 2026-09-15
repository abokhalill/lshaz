// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/memory_profile.h"

#include <algorithm>
#include <charconv>

namespace lshaz {

std::map<uint64_t, std::vector<const OffsetCoherence *>>
ObjectCoherence::linesOf(uint64_t lineBytes) const {
    std::map<uint64_t, std::vector<const OffsetCoherence *>> out;
    if (!lineBytes)
        return out;
    for (const auto &[off, oc] : byOffset)
        out[(off / lineBytes) * lineBytes].push_back(&oc);
    return out;
}

std::vector<uint64_t>
ObjectCoherence::falseSharedLines(uint64_t lineBytes) const {
    std::vector<uint64_t> out;
    for (const auto &[base, offs] : linesOf(lineBytes)) {
        if (offs.size() < 2)
            continue;
        std::set<unsigned> cores;
        for (const auto *o : offs)
            cores.insert(o->cpus.begin(), o->cpus.end());
        if (cores.size() >= 2)
            out.push_back(base);
    }
    return out;
}

unsigned ObjectCoherence::meanCycles() const {
    uint64_t sum = 0, n = 0;
    for (const auto &[off, oc] : byOffset) {
        sum += oc.weightSum;
        n += oc.weightCount;
    }
    return n ? static_cast<unsigned>(sum / n) : 0;
}

std::vector<const LineNeighbour *>
ObjectCoherence::neighboursOnLine(uint64_t lineBase, uint64_t lineBytes) const {
    std::vector<const LineNeighbour *> out;
    if (!lineBytes) return out;
    for (const auto &n : neighbours)
        if (n.witness >= lineBase && n.witness < lineBase + lineBytes)
            out.push_back(&n);
    return out;
}

const char *sharingVerdictName(SharingVerdict v) {
    switch (v) {
        case SharingVerdict::NoTraffic:       return "no-traffic";
        case SharingVerdict::OffClaimedLines: return "off-claimed-lines";
        case SharingVerdict::TooFewSamples:   return "too-few-samples";
        case SharingVerdict::SingleField:     return "single-field";
        case SharingVerdict::MultiField:      return "multi-field";
        case SharingVerdict::CrossObjectLine: return "cross-object-line";
    }
    return "no-traffic";
}

SharingEvidence discriminateSharing(const ObjectCoherence &oc,
                                    const std::vector<ClaimedField> &claimed,
                                    uint64_t lineBytes) {
    SharingEvidence e;
    e.samplesOnObject = oc.samples;
    if (!lineBytes || claimed.empty() || oc.byOffset.empty())
        return e;

    // A field wider than the gap to the next boundary belongs to every line its
    // bytes touch, so a straddling field is not lost from the line where the
    // traffic happened to land.
    std::map<uint64_t, std::vector<const ClaimedField *>> byLine;
    for (const auto &f : claimed) {
        const uint64_t last = f.offset + (f.size ? f.size - 1 : 0);
        for (uint64_t b = (f.offset / lineBytes) * lineBytes; b <= last;
             b += lineBytes)
            byLine[b].push_back(&f);
    }

    struct LineTally {
        uint64_t samples = 0;
        std::set<unsigned> cores;
        std::map<std::string, uint64_t> fieldSamples;
        std::vector<uint64_t> unclaimed;
    };
    std::map<uint64_t, LineTally> tally;

    for (const auto &[off, oc2] : oc.byOffset) {
        const uint64_t base = (off / lineBytes) * lineBytes;
        auto fl = byLine.find(base);
        if (fl == byLine.end())
            continue;
        auto &t = tally[base];
        t.samples += oc2.samples;
        t.cores.insert(oc2.cpus.begin(), oc2.cpus.end());
        const ClaimedField *hit = nullptr;
        for (const auto *f : fl->second)
            if (f->contains(off)) { hit = f; break; }
        if (hit) t.fieldSamples[hit->name] += oc2.samples;
        else     t.unclaimed.push_back(off);
    }

    if (tally.empty()) {
        e.verdict = oc.samples ? SharingVerdict::OffClaimedLines
                               : SharingVerdict::NoTraffic;
        for (const auto &[off, unused] : oc.byOffset)
            e.unclaimedOffsets.push_back(off);
        return e;
    }

    // Lowest offset breaks a tie, so the reported line does not depend on map
    // iteration order changing under a different sample distribution.
    const uint64_t best = std::max_element(
        tally.begin(), tally.end(),
        [](const auto &a, const auto &b) {
            return a.second.samples != b.second.samples
                       ? a.second.samples < b.second.samples
                       : a.first > b.first;
        })->first;
    const LineTally &t = tally[best];

    e.lineBase = best;
    e.samplesOnLine = t.samples;
    e.cores = t.cores;
    e.unclaimedOffsets = t.unclaimed;

    std::vector<std::pair<std::string, uint64_t>> hits(t.fieldSamples.begin(),
                                                       t.fieldSamples.end());
    std::stable_sort(hits.begin(), hits.end(),
                     [](const auto &a, const auto &b) {
                         return a.second > b.second;
                     });
    for (const auto &[name, n] : hits)
        e.fieldsHit.push_back(name);

    for (const auto *n : oc.neighboursOnLine(best, lineBytes))
        e.lineNeighbours.push_back(n->objectId);

    if (t.samples < kMinSamplesToEstablish)
        e.verdict = SharingVerdict::TooFewSamples;
    else if (e.fieldsHit.size() >= 2)
        e.verdict = SharingVerdict::MultiField;
    else if (!e.lineNeighbours.empty())
        // A different object shares this line, so traffic landing in one field
        // does not mean one field is contended. Measured on an i9-9900K: a
        // read-only flag took 9727 samples because a counter eight bytes below
        // it was written from another core. Calling that field contention
        // names the wrong cause and recommends the wrong fix.
        e.verdict = SharingVerdict::CrossObjectLine;
    else if (t.samples < kMinSamplesToDiscriminate)
        e.verdict = SharingVerdict::TooFewSamples;
    else if (e.fieldsHit.size() == 1)
        e.verdict = SharingVerdict::SingleField;
    else
        // Enough traffic on the line, none of it inside a field the rule named.
        e.verdict = SharingVerdict::OffClaimedLines;
    return e;
}

double MemoryProfile::shareOf(const std::string &objectId) const {
    // Against everything the hardware sampled, not against what we managed to
    // name. On a heap-heavy target only a sixth of the traffic resolves, and
    // dividing by the named subset reports the one object we recognised as
    // 100% of the machine's coherence traffic.
    const uint64_t all = totalSamples + unresolvedSamples;
    if (!all)
        return 0.0;
    auto it = objects.find(objectId);
    return it == objects.end()
               ? 0.0
               : static_cast<double>(it->second.samples) / all;
}

const ObjectCoherence *MemoryProfile::find(const std::string &objectId) const {
    auto it = objects.find(objectId);
    return it == objects.end() ? nullptr : &it->second;
}

namespace {

// Small hand parser rather than a dependency, matching shard_ipc's choice and
// for the same reason: the wire is ours on both ends.
struct P {
    const std::string &s;
    size_t i = 0;
    explicit P(const std::string &t) : s(t) {}

    void ws() {
        while (i < s.size() &&
               (s[i] == ' ' || s[i] == '\n' || s[i] == '\r' || s[i] == '\t'))
            ++i;
    }
    bool take(char c) { ws(); if (i < s.size() && s[i] == c) { ++i; return true; }
                        return false; }
    bool peek(char c) { ws(); return i < s.size() && s[i] == c; }

    std::string str() {
        ws();
        if (i >= s.size() || s[i] != '"') { skip(); return {}; }
        ++i;
        std::string o;
        while (i < s.size() && s[i] != '"') {
            if (s[i] == '\\' && i + 1 < s.size()) {
                ++i;
                switch (s[i]) {
                    case 'n': o += '\n'; break;
                    case 't': o += '\t'; break;
                    case 'r': o += '\r'; break;
                    default:  o += s[i];
                }
            } else o += s[i];
            ++i;
        }
        if (i < s.size()) ++i;
        return o;
    }

    uint64_t num() {
        ws();
        const size_t start = i;
        while (i < s.size() && ((s[i] >= '0' && s[i] <= '9') || s[i] == '-' ||
                                s[i] == '.' || s[i] == 'e' || s[i] == 'E' ||
                                s[i] == '+'))
            ++i;
        if (start == i) { skip(); return 0; }
        uint64_t v = 0;
        std::from_chars(s.data() + start, s.data() + i, v);
        return v;
    }

    // A neighbour offset is negative when the other object comes first, and
    // num() parses into an unsigned, so -8 would arrive as a huge positive.
    int64_t snum() {
        ws();
        const bool neg = i < s.size() && s[i] == '-';
        if (neg) ++i;
        return neg ? -(int64_t)num() : (int64_t)num();
    }

    // Always advances when input remains, so a malformed document cannot spin
    // a caller's loop. Same guarantee shard_ipc's parser makes.
    void skip() {
        ws();
        if (i >= s.size()) return;
        if (s[i] == '"') { str(); return; }
        if (s[i] == '{' || s[i] == '[') {
            const char open = s[i], close = open == '{' ? '}' : ']';
            ++i;
            int d = 1;
            while (i < s.size() && d) {
                if (s[i] == '"') { str(); continue; }
                if (s[i] == open) ++d;
                else if (s[i] == close) --d;
                ++i;
            }
            return;
        }
        while (i < s.size() && s[i] != ',' && s[i] != '}' && s[i] != ']') ++i;
    }
};

void parseOffsets(P &p, ObjectCoherence &oc) {
    if (!p.take('[')) { p.skip(); return; }
    while (!p.peek(']') && p.i < p.s.size()) {
        if (!p.take('{')) { p.skip(); break; }
        OffsetCoherence o;
        while (!p.peek('}') && p.i < p.s.size()) {
            const std::string k = p.str();
            p.take(':');
            if (k == "offset")        o.offset = p.num();
            else if (k == "samples")  o.samples = p.num();
            else if (k == "weightSum")   o.weightSum = p.num();
            else if (k == "weightCount") o.weightCount = p.num();
            else if (k == "cpus") {
                if (p.take('[')) {
                    while (!p.peek(']') && p.i < p.s.size()) {
                        o.cpus.insert(static_cast<unsigned>(p.num()));
                        p.take(',');
                    }
                    p.take(']');
                } else p.skip();
            } else p.skip();
            p.take(',');
        }
        p.take('}');
        oc.cpus.insert(o.cpus.begin(), o.cpus.end());
        oc.byOffset[o.offset] = std::move(o);
        p.take(',');
    }
    p.take(']');
}

void parseNeighbours(P &p, ObjectCoherence &oc) {
    if (!p.take('[')) { p.skip(); return; }
    while (!p.peek(']') && p.i < p.s.size()) {
        if (!p.take('{')) { p.skip(); break; }
        LineNeighbour n;
        while (!p.peek('}') && p.i < p.s.size()) {
            const std::string k = p.str();
            p.take(':');
            if (k == "id")      n.objectId = p.str();
            else if (k == "at") n.at = p.snum();
            else if (k == "witness") n.witness = p.num();
            else p.skip();
            p.take(',');
        }
        p.take('}');
        if (!n.objectId.empty()) oc.neighbours.push_back(std::move(n));
        p.take(',');
    }
    p.take(']');
}

} // namespace

bool parseMemoryProfile(const std::string &json, MemoryProfile &out,
                        std::string &err) {
    P p(json);
    if (!p.take('{')) { err = "not a JSON object"; return false; }
    bool sawObjects = false, sawKind = false;
    while (!p.peek('}') && p.i < json.size()) {
        const std::string k = p.str();
        p.take(':');
        if (k == "kind") {
            sawKind = p.str() == "lshaz.memory-profile";
        } else if (k == "origin")   out.origin = p.str();
        else if (k == "machine")    out.machine = p.str();
        else if (k == "workload")   out.workload = p.str();
        else if (k == "event")      out.event = p.str();
        else if (k == "cpu")        out.cpuModel = p.str();
        else if (k == "selfTest")   out.selfTest = p.str();
        else if (k == "selfTestSamples") out.selfTestSamples = p.num();
        else if (k == "storeOnlySharing") out.storeOnlySharing = p.str();
        else if (k == "samplePeriod") out.samplePeriod = p.num();
        else if (k == "wallNanos")    out.wallNanos = p.num();
        else if (k == "unresolvedSamples") out.unresolvedSamples = p.num();
        else if (k == "objects") {
            sawObjects = true;
            if (!p.take('[')) { p.skip(); p.take(','); continue; }
            while (!p.peek(']') && p.i < json.size()) {
                if (!p.take('{')) { p.skip(); break; }
                ObjectCoherence oc;
                while (!p.peek('}') && p.i < json.size()) {
                    const std::string ok = p.str();
                    p.take(':');
                    if (ok == "id")           oc.objectId = p.str();
                    else if (ok == "samples") oc.samples = p.num();
                    else if (ok == "offsets") parseOffsets(p, oc);
                    else if (ok == "neighbours") parseNeighbours(p, oc);
                    else p.skip();
                    p.take(',');
                }
                p.take('}');
                if (!oc.objectId.empty()) {
                    out.totalSamples += oc.samples;
                    out.objects[oc.objectId] = std::move(oc);
                }
                p.take(',');
            }
            p.take(']');
        } else p.skip();
        p.take(',');
    }
    if (!sawKind) {
        err = "missing \"kind\": \"lshaz.memory-profile\"; this is not a "
              "profile this tool wrote";
        return false;
    }
    if (!sawObjects) {
        err = "no objects array: a profile with no storage in it would read "
              "like a machine that saw nothing";
        return false;
    }
    return true;
}

} // namespace lshaz
