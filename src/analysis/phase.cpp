// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/phase.h"

#include <deque>
#include <vector>
#include <map>

namespace lshaz {

namespace {

constexpr unsigned kNoSpawn = std::numeric_limits<unsigned>::max();

// Callers of each function, and every name the graph mentions. Library
// callees appear here too; they have no outgoing edges and drop out of the
// partition on their own.
struct Graph {
    std::map<std::string, std::set<std::string>> callers;
    std::set<std::string> universe;
};

Graph buildGraph(const ThreadRoleSummary &facts) {
    Graph g;
    for (const auto &[caller, callees] : facts.callEdges) {
        g.universe.insert(caller);
        for (const auto &callee : callees) {
            g.universe.insert(callee);
            g.callers[callee].insert(caller);
        }
    }
    g.universe.insert(facts.definedFunctions.begin(),
                      facts.definedFunctions.end());
    return g;
}

// Functions that may create a thread before returning, and the callee
// signatures through which an indirect call can reach one.
//
// Both sets only grow, so the outer loop terminates: it runs once more for
// each newly spawn-capable signature, and there are finitely many.
struct SpawnSolution {
    std::set<std::string> spawning;
    std::set<std::string> spawnSignatures;
    std::string witness;  // an address-taken spawner, for reporting

    // What put each function in the set: the next function toward a thread
    // creation, and how the edge was resolved. A thin partition is always one
    // function spawning that nobody expected to, and the chain is the only
    // thing that says which resolution step was the weak one.
    struct Edge {
        std::string next;   // empty at a direct thread-creation site
        std::string how;    // empty for a direct call edge
    };
    std::map<std::string, Edge> via;

    std::string chainFrom(const std::string &fn) const {
        std::string out = fn;
        std::set<std::string> seen{fn};
        for (auto it = via.find(fn); it != via.end() && !it->second.next.empty();
             it = via.find(it->second.next)) {
            if (!seen.insert(it->second.next).second) {
                out += " -> ...";
                break;
            }
            if (!it->second.how.empty()) out += " " + it->second.how;
            out += " -> " + it->second.next;
        }
        return out;
    }
};

// What a parameter slot can hold, closed over the forwarding edges. A slot
// nobody filled with anything nameable stays opaque, and opaque propagates
// forward the same way the targets do.
struct SlotTargets {
    std::map<std::string, std::set<std::string>> targets;
    std::set<std::string> opaque;
};

SlotTargets solveSlots(const ThreadRoleSummary &facts) {
    SlotTargets out;
    out.targets = facts.fnSlotTargets;
    out.opaque = facts.fnSlotOpaque;
    // Slots are few and chains are short, so a sweep to fixpoint beats a
    // worklist with its reverse index.
    for (bool changed = true; changed;) {
        changed = false;
        for (const auto &[slot, sources] : facts.fnSlotForwards) {
            auto &dst = out.targets[slot];
            const bool wasOpaque = out.opaque.count(slot) > 0;
            bool nowOpaque = wasOpaque;
            for (const auto &src : sources) {
                auto it = out.targets.find(src);
                if (it != out.targets.end()) {
                    const size_t before = dst.size();
                    dst.insert(it->second.begin(), it->second.end());
                    if (dst.size() != before) changed = true;
                }
                // A source with no target, no forward and no opacity holds
                // nothing: every write to a slot records one of the three,
                // and field slots are keyed by type, so a struct copy moves
                // a pointer between two names that are already the same slot.
                if (out.opaque.count(src))
                    nowOpaque = true;
            }
            if (nowOpaque && !wasOpaque) {
                out.opaque.insert(slot);
                changed = true;
            }
        }
    }
    return out;
}

// Can a call through this slot reach a function that spawns?
//
// A slot nothing unnameable was ever written to answers exactly: the targets
// are the whole set. An opaque slot falls back to nothing, which is the
// conservative answer, because the point of tracking slots at all is that
// the signature answer is wrong: void *(void *) is both the pthread entry
// type and the generic C callback type, and matching on it connected a
// defrag callback to a worker thread on redis.
bool slotMaySpawn(const std::string &slot, const SlotTargets &slots,
                  const std::set<std::string> &spawning,
                  std::string *witness) {
    if (slots.opaque.count(slot)) {
        if (witness) *witness = "an unnameable value written to " + slot;
        return true;
    }
    auto it = slots.targets.find(slot);
    if (it == slots.targets.end())
        return false;
    for (const auto &t : it->second)
        if (spawning.count(t)) {
            if (witness) *witness = t;
            return true;
        }
    return false;
}

// Functions a call to which never returns. The attribute is the seed, not
// the answer: most codebases spell their fatal path as a plain void function
// whose body ends in abort, and taking that as returning puts the whole crash
// reporter downstream of every assertion in the tree.
std::set<std::string> solveNoReturn(const ThreadRoleSummary &facts) {
    std::set<std::string> out = facts.noReturnFunctions;

    std::map<std::string, std::set<std::string>> tailCallers;
    for (const auto &[caller, callee] : facts.tailCallee)
        tailCallers[callee].insert(caller);

    const auto countOf = [](const std::map<std::string, unsigned> &m,
                            const std::string &k) {
        auto it = m.find(k);
        return it == m.end() ? 0u : it->second;
    };

    for (bool outer = true; outer;) {
        outer = false;

        // Every call site of F is either followed by __builtin_unreachable or
        // is the tail call of a function that itself does not return. The
        // second clause is what recovers an assertion helper called from a
        // fatal wrapper: if F returned there, the wrapper would return too.
        //
        // Shrinking rather than growing, because the clause refers to the set
        // being computed: start with everything that could qualify and drop
        // what a non-returning caller fails to support.
        // A tail call is supported when nothing in this program observes the
        // callee returning there: the enclosing function does not return, or
        // it has no caller we compiled. The second covers an exported
        // assertion wrapper, whose only callers are modules loaded at run
        // time, and without it one such site keeps the helper it forwards to
        // out of the set and every assertion in the tree stays live.
        const auto tailSupported = [&](const std::string &g,
                                       const std::set<std::string> &cand) {
            return cand.count(g) || out.count(g) ||
                   countOf(facts.callSiteCount, g) == 0;
        };
        std::set<std::string> candidates;
        for (const auto &[fn, sites] : facts.callSiteCount) {
            if (!sites || out.count(fn)) continue;
            auto t = tailCallers.find(fn);
            const unsigned tails =
                t == tailCallers.end() ? 0u
                                       : static_cast<unsigned>(t->second.size());
            if (countOf(facts.unreachableAfterCount, fn) + tails >= sites)
                candidates.insert(fn);
        }
        for (bool shrank = true; shrank;) {
            shrank = false;
            std::vector<std::string> drop;
            for (const auto &fn : candidates) {
                unsigned supported = countOf(facts.unreachableAfterCount, fn);
                auto t = tailCallers.find(fn);
                if (t != tailCallers.end())
                    for (const auto &g : t->second)
                        if (tailSupported(g, candidates))
                            ++supported;
                if (supported < countOf(facts.callSiteCount, fn))
                    drop.push_back(fn);
            }
            for (const auto &fn : drop) {
                candidates.erase(fn);
                shrank = true;
            }
        }
        for (const auto &fn : candidates)
            if (out.insert(fn).second)
                outer = true;

        // A body that cannot return and whose last statement calls something
        // that does not return, does not return either.
        for (bool grew = true; grew;) {
            grew = false;
            for (const auto &[fn, tail] : facts.tailCallee) {
                if (out.count(fn) || facts.returningFunctions.count(fn))
                    continue;
                if (out.count(tail)) {
                    out.insert(fn);
                    grew = true;
                    outer = true;
                }
            }
        }
    }
    return out;
}

SpawnSolution solveSpawning(const ThreadRoleSummary &facts, const Graph &g,
                            const SlotTargets &slots,
                            const std::set<std::string> &noReturn) {
    SpawnSolution out;
    std::map<std::string, std::string> sigWitness;
    std::deque<std::string> work;
    const auto seed = [&](const std::string &fn, SpawnSolution::Edge why) {
        if (out.spawning.insert(fn).second) {
            out.via[fn] = std::move(why);
            work.push_back(fn);
        }
    };

    for (const auto &[fn, pos] : facts.spawnPoints) {
        (void)pos;
        seed(fn, {});
    }

    for (;;) {
        while (!work.empty()) {
            const std::string fn = work.front();
            work.pop_front();
            auto it = g.callers.find(fn);
            if (it == g.callers.end())
                continue;
            // A call that never returns cannot make the statement after it
            // concurrent, because that statement does not run.
            if (noReturn.count(fn))
                continue;
            for (const auto &caller : it->second)
                seed(caller, {fn, {}});
        }
        // Only a signature some address-taken spawner matches makes an
        // indirect call a spawn point. Without the filter, a checksum
        // dispatched through a function pointer spawns threads.
        bool grew = false;
        for (const auto &[sig, fns] : facts.addressTakenBySignature) {
            if (out.spawnSignatures.count(sig))
                continue;
            for (const auto &fn : fns) {
                if (!out.spawning.count(fn))
                    continue;
                out.spawnSignatures.insert(sig);
                sigWitness[sig] = fn;
                if (out.witness.empty()) out.witness = fn;
                grew = true;
                break;
            }
        }
        // A slot-resolved site can also become live as spawning grows, so
        // both kinds are rechecked every round rather than only the
        // signature ones.
        bool seeded = false;
        for (const auto &[caller, slotsAt] : facts.indirectSlotCalls) {
            if (out.spawning.count(caller))
                continue;
            for (const auto &[slot, pos] : slotsAt) {
                (void)pos;
                std::string w;
                if (!slotMaySpawn(slot, slots, out.spawning, &w))
                    continue;
                seed(caller, {w, "=[" + slot + "]="});
                seeded = true;
                break;
            }
        }
        for (const auto &[caller, sigs] : facts.indirectCalls) {
            if (out.spawning.count(caller))
                continue;
            for (const auto &[sig, pos] : sigs) {
                (void)pos;
                if (!out.spawnSignatures.count(sig))
                    continue;
                auto it = sigWitness.find(sig);
                seed(caller, {it == sigWitness.end() ? std::string() : it->second,
                              "=[" + sig + "]="});
                seeded = true;
                break;
            }
        }
        if (!grew && !seeded)
            break;
    }
    return out;
}

// Earliest statement in F at which a thread may already exist. kNoSpawn when
// nothing in F spawns.
std::map<std::string, unsigned>
earliestSpawnPerFunction(const ThreadRoleSummary &facts,
                         const SpawnSolution &spawn,
                         const SlotTargets &slots,
                         const std::set<std::string> &noReturn) {
    std::map<std::string, unsigned> out;
    const auto lower = [&](const std::string &fn, unsigned at) {
        auto [it, inserted] = out.emplace(fn, at);
        if (!inserted && at < it->second)
            it->second = at;
    };

    for (const auto &[fn, pos] : facts.spawnPoints)
        lower(fn, pos.first);

    for (const auto &[caller, callees] : facts.callEdges) {
        auto eo = facts.edgeOrder.find(caller);
        for (const auto &callee : callees) {
            if (!spawn.spawning.count(callee) || noReturn.count(callee))
                continue;
            unsigned at = 0;
            if (eo != facts.edgeOrder.end()) {
                auto p = eo->second.find(callee);
                if (p != eo->second.end())
                    at = p->second.first;
            }
            lower(caller, at);
        }
    }

    for (const auto &[caller, slotsAt] : facts.indirectSlotCalls)
        for (const auto &[slot, pos] : slotsAt)
            if (slotMaySpawn(slot, slots, spawn.spawning, nullptr))
                lower(caller, pos.first);

    for (const auto &[caller, sigs] : facts.indirectCalls)
        for (const auto &[sig, pos] : sigs)
            if (spawn.spawnSignatures.count(sig))
                lower(caller, pos.first);

    // A body whose statement numbering does not order execution spawns at
    // its own entry as far as anything downstream is concerned.
    for (const auto &fn : facts.orderUnknown) {
        auto it = out.find(fn);
        if (it != out.end())
            it->second = 0;
    }
    return out;
}

} // namespace

PhaseVerdicts computePhases(const ThreadRoleSummary &facts) {
    PhaseVerdicts v;
    const Graph g = buildGraph(facts);
    v.functionsSeen = static_cast<unsigned>(g.universe.size());
    const SlotTargets slots = solveSlots(facts);
    const std::set<std::string> noReturn = solveNoReturn(facts);
    const SpawnSolution spawn = solveSpawning(facts, g, slots, noReturn);
    v.spawning = spawn.spawning;
    v.indirectSpawnWitness = spawn.witness;

    if (facts.spawnPoints.empty()) {
        v.dark = true;
        v.darkReason =
            "no thread-creation call site anywhere in the scanned sources";
        return v;
    }
    if (!g.universe.count("main")) {
        v.dark = true;
        v.darkReason = "no main in the merged call graph to partition from";
        return v;
    }
    for (const auto &fn : facts.preMainFunctions) {
        if (v.spawning.count(fn)) {
            v.dark = true;
            v.darkReason = "'" + fn +
                           "' spawns before main runs, so no statement is on "
                           "the near side of the first thread creation";
            return v;
        }
    }

    const auto spawnAt =
        earliestSpawnPerFunction(facts, spawn, slots, noReturn);

    // What closes main's pre-thread window. A one-function partition on a
    // program with a long init chain means the cutoff landed on the first
    // statement, and the callee that put it there is the whole explanation.
    if (auto s = spawnAt.find("main"); s != spawnAt.end()) {
        std::string via;
        if (auto eo = facts.edgeOrder.find("main"); eo != facts.edgeOrder.end())
            for (const auto &[callee, p] : eo->second)
                if (p.first == s->second && v.spawning.count(callee)) {
                    via = callee;
                    break;
                }
        v.windowEnd = "main statement " + std::to_string(s->second);
        if (!via.empty())
            v.windowEnd += ", at the call to " + spawn.chainFrom(via);
        else if (facts.spawnPoints.count("main"))
            v.windowEnd += ", where main spawns directly";
        else if (!spawn.witness.empty() && facts.indirectCalls.count("main"))
            v.windowEnd += ", at an indirect call that may spawn because '" +
                           spawn.witness +
                           "' has its address taken and spawns";
    } else {
        v.windowEnd = "main reaches no spawn";
    }

    // false is provably pre-thread, true is concurrent, absent is unreached
    // and reads as concurrent. Only false ever flips, so the fixed point is
    // the least one and its value does not depend on the worklist order.
    std::map<std::string, bool> state;
    std::deque<std::string> work;
    const auto raise = [&](const std::string &fn, bool conc) {
        auto it = state.find(fn);
        if (it == state.end()) {
            state.emplace(fn, conc);
            work.push_back(fn);
        } else if (conc && !it->second) {
            it->second = true;
            work.push_back(fn);
        }
    };

    raise("main", false);
    for (const auto &fn : facts.threadEntries)
        raise(fn, true);
    // Anything the graph records no caller for may be an entry point, a
    // signal handler or a callback dispatched through a table. Assuming it
    // concurrent is the direction that cannot invent a refutation.
    for (const auto &fn : g.universe)
        if (fn != "main" && !g.callers.count(fn))
            raise(fn, true);

    while (!work.empty()) {
        const std::string caller = work.front();
        work.pop_front();
        const bool callerConc = state[caller];
        auto ce = facts.callEdges.find(caller);
        if (ce == facts.callEdges.end())
            continue;
        unsigned spawnFrom = kNoSpawn;
        if (auto s = spawnAt.find(caller); s != spawnAt.end())
            spawnFrom = s->second;
        auto eo = facts.edgeOrder.find(caller);
        for (const auto &callee : ce->second) {
            bool conc = callerConc;
            if (!conc && spawnFrom != kNoSpawn) {
                // Reached by the spawn unless every call site of this callee
                // is strictly above it. An unpositioned edge is treated as
                // reached: a missing number is not evidence of order.
                unsigned last = kNoSpawn;
                if (eo != facts.edgeOrder.end()) {
                    auto p = eo->second.find(callee);
                    if (p != eo->second.end())
                        last = p->second.last;
                }
                conc = last >= spawnFrom;
            }
            raise(callee, conc);
        }
    }

    for (const auto &[fn, conc] : state)
        if (!conc)
            v.preThread.insert(fn);
    return v;
}

} // namespace lshaz
