// SPDX-License-Identifier: Apache-2.0
//
// Andersen-style inclusion-based points-to, field-sensitive on a byte offset,
// flow-insensitive, solved once in the reduce phase over the merged constraint
// set from every shard.

#include "lshaz/analysis/memory.h"

#include <algorithm>

namespace lshaz {

namespace {

// An offset-qualified reference. Objects stay whole and the offset rides on
// the edge, so a record with 300 fields is one object and not 300.
std::string at(const std::string &object, uint64_t offset) {
    if (offset == 0 || obj::isUnresolved(object))
        return object;
    return object + "+" + std::to_string(offset);
}

} // namespace

bool PendingAccess::operator<(const PendingAccess &o) const {
    if (base != o.base) return base < o.base;
    if (offset != o.offset) return offset < o.offset;
    if (function != o.function) return function < o.function;
    if (site != o.site) return site < o.site;
    if (isWrite != o.isWrite) return isWrite < o.isWrite;
    return size < o.size;
}

const std::set<std::string> &PointsToSolution::of(const std::string &p) const {
    static const std::set<std::string> empty;
    auto it = pointsTo.find(p);
    return it == pointsTo.end() ? empty : it->second;
}

bool PointsToSolution::resolves(const std::string &p) const {
    auto it = pointsTo.find(p);
    return it != pointsTo.end() && !it->second.empty();
}

std::set<std::string> ObjectAccess::writers() const {
    std::set<std::string> out;
    for (const auto &[off, a] : byOffset)
        out.insert(a.writers.begin(), a.writers.end());
    return out;
}

std::set<std::string> ObjectAccess::readers() const {
    std::set<std::string> out;
    for (const auto &[off, a] : byOffset)
        out.insert(a.readers.begin(), a.readers.end());
    return out;
}

PointsToSolution solvePointsTo(const std::set<Constraint> &constraints,
                               unsigned objectBudget) {
    PointsToSolution sol;

    // Complex constraints indexed by the pointer whose points-to set drives
    // them, so a change to pts(p) revisits only what depends on p.
    std::map<std::string, std::vector<const Constraint *>> loadsOn, storesOn;
    std::map<std::string, std::set<std::string>> copyEdges; // q -> {p} meaning pts(q) flows to pts(p)

    std::set<std::string> work;

    for (const auto &c : constraints) {
        switch (c.kind) {
            case Constraint::Kind::AddrOf:
                if (sol.pointsTo[c.lhs].insert(at(c.rhs, c.offset)).second)
                    work.insert(c.lhs);
                break;
            case Constraint::Kind::Copy:
                copyEdges[c.rhs].insert(c.lhs);
                if (sol.pointsTo.count(c.rhs))
                    work.insert(c.rhs);
                break;
            case Constraint::Kind::Load:
                loadsOn[c.rhs].push_back(&c);
                if (sol.pointsTo.count(c.rhs))
                    work.insert(c.rhs);
                break;
            case Constraint::Kind::Store:
                storesOn[c.lhs].push_back(&c);
                if (sol.pointsTo.count(c.lhs))
                    work.insert(c.lhs);
                break;
        }
    }

    unsigned pairs = 0;
    for (const auto &[p, s] : sol.pointsTo) pairs += s.size();

    // Least fixed point. Monotone: sets only grow, the lattice is finite, so
    // this terminates and lands on the same solution whatever order the
    // worklist drains in.
    while (!work.empty()) {
        const std::string p = *work.begin();
        work.erase(work.begin());
        ++sol.iterations;

        const std::set<std::string> targets = sol.pointsTo[p];

        auto flow = [&](const std::string &from, const std::string &to) {
            if (from == to) return;
            auto srcIt = sol.pointsTo.find(from);
            if (srcIt == sol.pointsTo.end() || srcIt->second.empty()) return;
            const std::set<std::string> src = srcIt->second;
            auto &dst = sol.pointsTo[to];
            const size_t before = dst.size();
            dst.insert(src.begin(), src.end());
            const size_t added = dst.size() - before;
            if (added == 0) return;
            pairs += static_cast<unsigned>(added);
            if (pairs > objectBudget) {
                sol.truncated = true;
                return;
            }
            work.insert(to);
        };

        auto edge = copyEdges.find(p);
        if (edge != copyEdges.end()) {
            const std::set<std::string> dests = edge->second;
            for (const auto &dest : dests)
                flow(p, dest);
        }

        // A dereference is not a one-time transfer. The object read through
        // may gain targets long after this load was first seen, so the load
        // installs a standing edge and lets the worklist carry the rest.
        auto ld = loadsOn.find(p);
        if (ld != loadsOn.end())
            for (const Constraint *c : ld->second)
                for (const auto &o : targets) {
                    const std::string src = at(o, c->offset);
                    copyEdges[src].insert(c->lhs);
                    flow(src, c->lhs);
                }

        auto st = storesOn.find(p);
        if (st != storesOn.end())
            for (const Constraint *c : st->second)
                for (const auto &o : targets) {
                    const std::string dst = at(o, c->offset);
                    copyEdges[c->rhs].insert(dst);
                    flow(c->rhs, dst);
                }

        if (sol.truncated)
            break;
    }

    std::set<std::string> distinct;
    for (const auto &[p, s] : sol.pointsTo)
        for (const auto &o : s)
            distinct.insert(o);
    sol.objectsDiscovered = static_cast<unsigned>(distinct.size());

    return sol;
}

MemoryModel buildMemoryModel(const MemorySummary &merged,
                             const PointsToSolution &solution) {
    MemoryModel model;
    model.unnameableAccesses = merged.unnameableAccesses;

    for (const auto &a : merged.accesses) {
        // A base naming storage directly needs no resolution: `g_stats.hits`
        // is the object, not a pointer to it.
        std::set<std::string> bases;
        if (!obj::isCell(a.base) && !obj::isUnresolved(a.base) &&
            !solution.resolves(a.base)) {
            bases.insert(a.base);
        } else {
            for (const auto &o : solution.of(a.base))
                bases.insert(o);
        }

        if (bases.empty()) {
            ++model.unresolvedAccesses;
            continue;
        }

        bool landed = false;
        for (const auto &base : bases) {
            // Strip any offset the solver attached; the access carries its own.
            std::string object = base;
            uint64_t baseOffset = 0;
            const auto plus = base.rfind('+');
            if (plus != std::string::npos &&
                base.find_first_not_of("0123456789", plus + 1) ==
                    std::string::npos) {
                object = base.substr(0, plus);
                baseOffset = std::stoull(base.substr(plus + 1));
            }
            if (obj::isUnresolved(object) || obj::isCell(object))
                continue;

            auto &slot = model.objects[object].byOffset[baseOffset + a.offset];
            slot.offset = baseOffset + a.offset;
            slot.size = std::max(slot.size, a.size);
            if (slot.fieldName.empty()) slot.fieldName = a.fieldName;
            slot.isAtomic |= a.isAtomic;
            if (a.isWrite) {
                slot.writers.insert(a.function);
                if (!a.site.empty()) slot.writeSites.insert(a.site);
                if (a.inLoop) ++slot.loopWriteSites;
            } else {
                slot.readers.insert(a.function);
            }
            landed = true;
        }

        if (landed)
            ++model.resolvedAccesses;
        else
            ++model.unresolvedAccesses;
    }

    return model;
}

} // namespace lshaz
