// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lshaz {

// A whole-program abstract memory location.
//
// Everything cross-TU in lshaz used to join on the record's type name, which
// makes two globals of one type a single object and a heap block no object at
// all. An ObjectId names storage instead, and every form of it is built from
// something that survives a translation unit boundary: a linker symbol, a
// source location, a function name plus a parameter index.
//
// Encoded as a string because it crosses the shard IPC boundary and is a map
// key on both sides. The prefix is the discriminator:
//
//   g:<symbol>        file-scope object
//   h:<file>:<line>   allocation site
//   s:<fn>::<var>     stack local
//   p:<fn>#<n>        formal parameter cell
//   r:<fn>            return cell
//   ?                 unresolved
//
// "?" is not a bucket that absorbs what the analysis could not do. An access
// based on it is counted and reported separately and never merges into a real
// object, for the same reason ClaimState has Unknown: a question nobody
// answered must not read as an answer.
namespace obj {

inline std::string global(const std::string &symbol) { return "g:" + symbol; }
inline std::string heap(const std::string &file, unsigned line) {
    return "h:" + file + ":" + std::to_string(line);
}
inline std::string stack(const std::string &fn, const std::string &var) {
    return "s:" + fn + "::" + var;
}
inline std::string param(const std::string &fn, unsigned index) {
    return "p:" + fn + "#" + std::to_string(index);
}
inline std::string ret(const std::string &fn) { return "r:" + fn; }

inline const char *unresolved() { return "?"; }
inline bool isUnresolved(const std::string &id) { return id == "?"; }

// Storage that exists for the whole program and that any thread reaching the
// symbol reaches the same copy of. The distinction the old standing/handed
// majority vote was approximating.
inline bool isStatic(const std::string &id) { return id.rfind("g:", 0) == 0; }
inline bool isHeap(const std::string &id) { return id.rfind("h:", 0) == 0; }
inline bool isStack(const std::string &id) { return id.rfind("s:", 0) == 0; }

// Cells exist to carry constraints between functions and are not storage a
// program can contend over. They are solved through, never reported.
inline bool isCell(const std::string &id) {
    return id.rfind("p:", 0) == 0 || id.rfind("r:", 0) == 0;
}

} // namespace obj

// A points-to constraint. Field sensitivity rides on the offset rather than
// on a separate object per field, which keeps the object count linear.
struct Constraint {
    enum class Kind : uint8_t { AddrOf, Copy, Load, Store };

    Kind kind = Kind::Copy;
    std::string lhs;       // pointer being defined, or stored through
    std::string rhs;       // object taken, or pointer read from
    uint64_t offset = 0;   // byte offset applied to the dereference

    bool operator<(const Constraint &o) const {
        if (kind != o.kind) return kind < o.kind;
        if (lhs != o.lhs) return lhs < o.lhs;
        if (rhs != o.rhs) return rhs < o.rhs;
        return offset < o.offset;
    }
    bool operator==(const Constraint &o) const {
        return kind == o.kind && lhs == o.lhs && rhs == o.rhs &&
               offset == o.offset;
    }
};

// One memory access, before the base pointer has been resolved to an object.
// The map phase cannot resolve it: the constraint that settles a parameter
// lives in the caller's TU.
struct PendingAccess {
    std::string base;      // pointer expression's symbolic name
    uint64_t offset = 0;   // field offset within the pointee
    uint64_t size = 0;
    std::string function;  // enclosing function, for thread-role attribution
    std::string site;      // basename:line
    bool isWrite = false;
    bool inLoop = false;
    bool isAtomic = false;
    std::string fieldName; // for reporting, not for identity

    bool operator<(const PendingAccess &o) const;
};

// Per-TU partial: constraints and unresolved accesses, both of which mean
// nothing alone and everything merged.
struct MemorySummary {
    std::set<Constraint> constraints;
    std::vector<PendingAccess> accesses;

    // Accesses the front end could not name a base for at all. Counted so a
    // thin solution is visible as a thin solution.
    unsigned unnameableAccesses = 0;

    void merge(const MemorySummary &o) {
        constraints.insert(o.constraints.begin(), o.constraints.end());
        accesses.insert(accesses.end(), o.accesses.begin(), o.accesses.end());
        unnameableAccesses += o.unnameableAccesses;
    }
};

// The solved points-to relation.
//
// Andersen's is a monotone fixed point over a finite lattice, so the least
// solution is unique: worklist order, shard count and arrival order cannot
// change it. Every other cross-TU pass here is deterministic because its
// iteration order is controlled; this one is deterministic because no other
// answer exists.
struct PointsToSolution {
    std::map<std::string, std::set<std::string>> pointsTo;

    // Hit the object budget, so the solution is a lower bound rather than the
    // fixed point. Reported, never silently absorbed.
    bool truncated = false;
    unsigned iterations = 0;
    unsigned objectsDiscovered = 0;

    const std::set<std::string> &of(const std::string &p) const;
    bool resolves(const std::string &p) const;
};

// Solve to the least fixed point. objectBudget bounds the total points-to
// pairs; exceeding it sets truncated rather than dropping work quietly.
PointsToSolution solvePointsTo(const std::set<Constraint> &constraints,
                               unsigned objectBudget = 2000000);

// One abstract object's accesses, after resolution.
struct ObjectAccess {
    struct At {
        uint64_t offset = 0;
        uint64_t size = 0;
        std::string fieldName;
        std::set<std::string> writers;   // functions
        std::set<std::string> readers;
        std::set<std::string> writeSites;
        unsigned loopWriteSites = 0;
        bool isAtomic = false;
    };
    std::map<uint64_t, At> byOffset;

    std::set<std::string> writers() const;
    std::set<std::string> readers() const;
};

// The whole-program access model, keyed by object rather than by type.
struct MemoryModel {
    std::map<std::string, ObjectAccess> objects;

    // Accesses whose base did not resolve to any object. The model's own
    // coverage number: a scan that resolved a tenth of its accesses must not
    // look like a scan that found nothing to report.
    unsigned resolvedAccesses = 0;
    unsigned unresolvedAccesses = 0;
    unsigned unnameableAccesses = 0;

    double resolutionRate() const {
        const unsigned total =
            resolvedAccesses + unresolvedAccesses + unnameableAccesses;
        return total == 0 ? 0.0
                          : static_cast<double>(resolvedAccesses) / total;
    }
};

// Resolve every pending access against the solution and bin by object.
MemoryModel buildMemoryModel(const MemorySummary &merged,
                             const PointsToSolution &solution);

} // namespace lshaz
