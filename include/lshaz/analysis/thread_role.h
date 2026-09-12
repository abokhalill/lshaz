// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/cost.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace lshaz {

// Per-TU thread-attribution facts, keyed by function/field name so they
// join across TUs (a pthread_create call and its entry's definition are
// usually in different TUs).
//
// Ordered containers throughout: IPC serialization and reduce iteration
// must not depend on hash-table layout.
struct ThreadRoleSummary {
    // Functions observed passed to a thread-creation primitive
    // (pthread_create, thrd_create, std::thread/jthread, std::async).
    std::set<std::string> threadEntries;

    // Direct call edges among user functions: caller -> callees.
    std::map<std::string, std::set<std::string>> callEdges;

    // "type_name::field_name" -> functions writing that field in this TU.
    std::map<std::string, std::set<std::string>> fieldWriters;

    // Same key, functions that only read the field. A store invalidates the
    // whole line, so a reader of a neighbouring field pays the same miss a
    // second writer would; establishing that needs both sides, and the store
    // and the read are routinely compiled apart.
    std::map<std::string, std::set<std::string>> fieldReaders;

    // How a field is touched, not just by whom. Per-TU partials that sum in
    // reduce, so thresholds land on the program total instead of on whatever
    // one shard happened to compile.
    //
    // Standing versus handed is what makes single-field contention detectable
    // at all: `g_stats.hits++` names a fixed object every thread shares,
    // `io->len = n` writes whatever the caller passed in and contends with
    // nothing. Writer counts can't tell them apart.
    struct FieldAccessFacts {
        unsigned writeSites = 0;
        unsigned loopWriteSites = 0;
        unsigned standingWriteSites = 0;
        unsigned handedWriteSites = 0;
        unsigned readSites = 0;
        unsigned standingReadSites = 0;
        unsigned handedReadSites = 0;

        void merge(const FieldAccessFacts &o) {
            writeSites += o.writeSites;
            loopWriteSites += o.loopWriteSites;
            standingWriteSites += o.standingWriteSites;
            handedWriteSites += o.handedWriteSites;
            readSites += o.readSites;
            standingReadSites += o.standingReadSites;
            handedReadSites += o.handedReadSites;
        }
        bool empty() const {
            return writeSites == 0 && readSites == 0;
        }
        // Ties go to handed. An even split is a type used both ways, and
        // calling that standing fires on every per-request struct there is.
        bool standing() const {
            return standingWriteSites > handedWriteSites;
        }

        // Same question, asked of the reads, because sometimes only the
        // reads know: a setter writing through its parameter cannot tell that
        // the command path reads the one global instance.
        bool standingReads() const {
            return standingReadSites > handedReadSites;
        }

        // Presence, not majority. One load of the shared instance on the
        // command path costs a transfer per store however many other sites
        // read an object handed in as a parameter. Majority still sets how
        // much we trust it, above.
        bool anyStandingRead() const { return standingReadSites > 0; }
    };
    std::map<std::string, FieldAccessFacts> fieldAccess;

    // Store locations as basename:line. The only join key to a hardware
    // profile that survives inlining, since the symbol does not.
    std::map<std::string, std::set<std::string>> fieldWriteSites;

    // Loop nesting per call site and per function. Hotness relaxation weighs
    // depth, and reduce reruns it over the merged graph rather than demoting
    // every cross-TU callee to the weakest grade.
    std::map<std::string, std::map<std::string, unsigned>> edgeLoopDepth;
    std::map<std::string, unsigned> ownLoopDepth;

    // The same quantity in milli, using the trip counts the source states.
    // Finer than edgeLoopDepth, which buckets it into four values; both stay
    // because hotness grades on nesting and cost grades on rate. Sparse: an
    // edge outside every loop just isn't here.
    std::map<std::string, std::map<std::string, Milli>> edgeFrequency;
    std::map<std::string, Milli> ownFrequency;

    // Functions that allocate, and functions that free, a block of a given
    // pointee type. The join key is the type name because it is the only
    // thing that crosses a TU boundary: the allocation and the free that
    // releases it routinely sit in different files, and no pointer value
    // survives the split. A site whose type cannot be named is left out,
    // which leaves FL020's conjunct unestablished rather than guessed.
    std::map<std::string, std::set<std::string>> allocatorsOfType;
    std::map<std::string, std::set<std::string>> freersOfType;

    // Raw structure for inferring the project's own allocator vocabulary
    // rather than being told it in config.
    //
    // returnForwards: F returns the result of calling G, so F allocates if G
    // does. paramForwards: F hands one of its own parameters to G, so F frees
    // if G does. Seeded from the libc primitives, which are ABI rather than
    // vocabulary, and closed over the merged graph in the reduce phase.
    std::map<std::string, std::set<std::string>> returnForwards;
    std::map<std::string, std::set<std::string>> paramForwards;

    // F passes a parameter to G unchanged, with no field access, arithmetic or
    // local in between. Locks need this stricter edge than frees do: a release
    // wrapper legitimately adjusts the pointer it frees, whereas
    // "handle(conn *c) { lock(&c->mtx); }" locks without being a lock wrapper,
    // and the relaxed edge makes every caller of it one too.
    std::map<std::string, std::set<std::string>> strictParamForwards;

    // Call sites keyed by callee: "F|T" meaning that inside F, the callee
    // produced (or was handed) a T*. Attribution waits for the reduce phase,
    // which is the first point that knows whether the callee allocates.
    std::map<std::string, std::set<std::string>> allocSitesByCallee;
    std::map<std::string, std::set<std::string>> freeSitesByCallee;

    // Seeds taken from the declaration's attributes rather than its spelling.
    // One `#define malloc(n) je_malloc(n)` defeats a name list everywhere in
    // the tree; the attributes survive preprocessing, and an allocator carries
    // them because the optimizer needs them.
    //
    // Produced only by the vocabulary prepass, which runs in the parent, so
    // these never cross the IPC boundary.
    std::set<std::string> declaredAllocators;
    std::set<std::string> declaredFreers;
    std::set<std::string> declaredLocks;
    std::set<std::string> declaredUnlocks;

    // A spin lock has no POSIX call and no attribute to find it by, only a
    // mechanism: an acquire is an atomic read-modify-write whose loop exits
    // when it succeeds, and the release is the same RMW with no loop.
    //
    // Keyed by the parameter's pointee type so the two sides can be paired.
    // Pairing is what separates a lock from a lock-free retry loop executing
    // the identical CAS: a queue push has no release counterpart on the same
    // type, and counting one as an acquire leaves FL012's nesting depth
    // permanently raised.
    std::map<std::string, std::set<std::string>> spinAcquireOfType;
    std::map<std::string, std::set<std::string>> spinReleaseOfType;

    // Types an atomic read-modify-write was performed on. A codebase wrapping
    // its atomics in a plain typedef has no _Atomic and no std::atomic
    // anywhere, so those fields do not exist as far as atomic detection is
    // concerned and the false-sharing rules read them as ordinary members.
    // Being the operand of a lock-prefixed RMW is what makes a type atomic;
    // the spelling never was.
    std::set<std::string> atomicTypes;

    // "F|i|G|j": inside F, the argument at position j of a call to G was
    // derived from F's own parameter i. Thread identity flows along these
    // edges, so a worker two hops from the entry is still indexing by thread.
    // Entries are almost always trampolines, which is why the identity cannot
    // stop at the entry's own body.
    std::set<std::string> identArgFlow;

    // A forward to a name absent here is a boundary the closure cannot cross,
    // not evidence that the wrapper does not allocate. Builtins are tracked
    // separately: memcpy has no body in any scan and never will, so counting
    // it as unresolved buries the boundaries that are.
    std::set<std::string> definedFunctions;
    std::set<std::string> builtinCallees;

    // Virtual methods some class actually overrides, qualified names. A call
    // to a method absent here is monomorphic program-wide, so it pays the
    // lost inline and not the mispredict. Only the merged set can say: the
    // override usually lives in another TU than the call.
    std::set<std::string> overriddenVirtuals;

    void merge(const ThreadRoleSummary &other) {
        threadEntries.insert(other.threadEntries.begin(),
                             other.threadEntries.end());
        for (const auto &[caller, callees] : other.callEdges)
            callEdges[caller].insert(callees.begin(), callees.end());
        for (const auto &[field, writers] : other.fieldWriters)
            fieldWriters[field].insert(writers.begin(), writers.end());
        for (const auto &[field, readers] : other.fieldReaders)
            fieldReaders[field].insert(readers.begin(), readers.end());
        for (const auto &[field, fa] : other.fieldAccess)
            fieldAccess[field].merge(fa);
        for (const auto &[field, locs] : other.fieldWriteSites)
            fieldWriteSites[field].insert(locs.begin(), locs.end());
        // Max, not overwrite: an inline body seen in several TUs must not
        // depend on which shard reported it last, or output stops being
        // jobs-invariant.
        for (const auto &[caller, edges] : other.edgeLoopDepth) {
            auto &dst = edgeLoopDepth[caller];
            for (const auto &[callee, d] : edges) {
                auto &cur = dst[callee];
                if (d > cur) cur = d;
            }
        }
        for (const auto &[fn, d] : other.ownLoopDepth) {
            auto &cur = ownLoopDepth[fn];
            if (d > cur) cur = d;
        }
        for (const auto &[caller, edges] : other.edgeFrequency) {
            auto &dst = edgeFrequency[caller];
            for (const auto &[callee, f] : edges) {
                auto &cur = dst[callee];
                if (f > cur) cur = f;
            }
        }
        for (const auto &[fn, f] : other.ownFrequency) {
            auto &cur = ownFrequency[fn];
            if (f > cur) cur = f;
        }
        for (const auto &[ty, fns] : other.allocatorsOfType)
            allocatorsOfType[ty].insert(fns.begin(), fns.end());
        for (const auto &[ty, fns] : other.freersOfType)
            freersOfType[ty].insert(fns.begin(), fns.end());
        for (const auto &[f, gs] : other.returnForwards)
            returnForwards[f].insert(gs.begin(), gs.end());
        for (const auto &[f, gs] : other.paramForwards)
            paramForwards[f].insert(gs.begin(), gs.end());
        for (const auto &[f, gs] : other.strictParamForwards)
            strictParamForwards[f].insert(gs.begin(), gs.end());
        for (const auto &[g, sites] : other.allocSitesByCallee)
            allocSitesByCallee[g].insert(sites.begin(), sites.end());
        for (const auto &[g, sites] : other.freeSitesByCallee)
            freeSitesByCallee[g].insert(sites.begin(), sites.end());
        declaredAllocators.insert(other.declaredAllocators.begin(),
                                  other.declaredAllocators.end());
        declaredFreers.insert(other.declaredFreers.begin(),
                              other.declaredFreers.end());
        declaredLocks.insert(other.declaredLocks.begin(),
                             other.declaredLocks.end());
        declaredUnlocks.insert(other.declaredUnlocks.begin(),
                               other.declaredUnlocks.end());
        for (const auto &[t, fns] : other.spinAcquireOfType)
            spinAcquireOfType[t].insert(fns.begin(), fns.end());
        for (const auto &[t, fns] : other.spinReleaseOfType)
            spinReleaseOfType[t].insert(fns.begin(), fns.end());
        atomicTypes.insert(other.atomicTypes.begin(), other.atomicTypes.end());
        identArgFlow.insert(other.identArgFlow.begin(),
                            other.identArgFlow.end());
        definedFunctions.insert(other.definedFunctions.begin(),
                                other.definedFunctions.end());
        builtinCallees.insert(other.builtinCallees.begin(),
                              other.builtinCallees.end());
        overriddenVirtuals.insert(other.overriddenVirtuals.begin(),
                                  other.overriddenVirtuals.end());
    }

    bool empty() const {
        return threadEntries.empty() && callEdges.empty() &&
               fieldWriters.empty();
    }
};

// Role bitmask. A function reachable from both roots is MAIN|WORKER and
// its writes attribute to both; the conservative direction: escalation
// requires provably disjoint masks.
enum ThreadRoleMask : uint8_t {
    ROLE_NONE   = 0,
    ROLE_MAIN   = 1,
    ROLE_WORKER = 2,
};

// Reduce-phase verdicts over the merged summary.
struct ThreadRoleVerdicts {
    // Only functions with a known role appear; absence means unknown.
    std::map<std::string, uint8_t> functionRoles;

    uint8_t roleOf(const std::string &fn) const {
        auto it = functionRoles.find(fn);
        return it != functionRoles.end() ? it->second : ROLE_NONE;
    }

    // Union of writer roles for a field. ROLE_NONE if any writer is
    // unknown; a partial attribution cannot prove disjointness.
    uint8_t fieldWriterRoles(const ThreadRoleSummary &facts,
                             const std::string &fieldKey) const {
        auto it = facts.fieldWriters.find(fieldKey);
        if (it == facts.fieldWriters.end() || it->second.empty())
            return ROLE_NONE;
        uint8_t mask = 0;
        for (const auto &w : it->second) {
            uint8_t r = roleOf(w);
            if (r == ROLE_NONE)
                return ROLE_NONE;
            mask |= r;
        }
        return mask;
    }

    // Union of roles over a named function set. ROLE_NONE if any member is
    // unattributed, since a partial answer cannot prove disjointness.
    uint8_t rolesOf(const std::set<std::string> &fns) const {
        if (fns.empty())
            return ROLE_NONE;
        uint8_t mask = 0;
        for (const auto &f : fns) {
            uint8_t r = roleOf(f);
            if (r == ROLE_NONE)
                return ROLE_NONE;
            mask |= r;
        }
        return mask;
    }

    // Roles over the attributed members, ignoring the rest.
    //
    // For "does this set reach two roles", never for disjointness. An
    // unattributed member can only add a role, so the subset is a sound lower
    // bound, while proving two sets disjoint needs all of both. A field read
    // from a hundred functions never has all hundred attributed, so the
    // strict form answers ROLE_NONE for exactly the fields that matter.
    uint8_t knownRolesOf(const std::set<std::string> &fns) const {
        uint8_t mask = ROLE_NONE;
        for (const auto &f : fns)
            mask |= roleOf(f);
        return mask;
    }

    // How many distinct roles the attributed members reach.
    static unsigned roleCount(uint8_t mask) {
        unsigned n = 0;
        for (; mask; mask &= mask - 1) ++n;
        return n;
    }

    // Every allocation of this type on one thread role, every free on the
    // other. The measured 25x is a property of that split, not of allocation
    // volume, so this is what FL020's conjunct gates on.
    bool typeIsFreedCrossThread(const ThreadRoleSummary &facts,
                                const std::string &typeName) const {
        auto a = facts.allocatorsOfType.find(typeName);
        auto f = facts.freersOfType.find(typeName);
        if (a == facts.allocatorsOfType.end() ||
            f == facts.freersOfType.end())
            return false;
        uint8_t am = rolesOf(a->second), fm = rolesOf(f->second);
        return am != ROLE_NONE && fm != ROLE_NONE && (am & fm) == 0;
    }

    // True when both fields have fully-attributed writers and the role
    // sets are disjoint and non-empty: every writer of A on one thread
    // role, every writer of B on the other.
    bool fieldsHaveDisjointWriterRoles(const ThreadRoleSummary &facts,
                                       const std::string &fieldA,
                                       const std::string &fieldB) const {
        uint8_t a = fieldWriterRoles(facts, fieldA);
        uint8_t b = fieldWriterRoles(facts, fieldB);
        return a != ROLE_NONE && b != ROLE_NONE && (a & b) == 0;
    }
};

// Closes the allocator and freer sets over the merged graph and turns the
// recorded call sites into allocatorsOfType / freersOfType. Seeded from the
// libc primitives only, so a project's own names are derived. extraAlloc adds
// configured patterns for what structure cannot reach: an allocator returning
// through an out-parameter, or one whose body this scan never saw.
//
// Mutates the two type maps in place; pure in its other inputs.
void inferAllocatorVocabulary(ThreadRoleSummary &facts,
                              const std::vector<std::string> &extraAlloc,
                              std::set<std::string> &allocatorsOut,
                              std::set<std::string> &freersOut);

// Mapping wrappers, closed over the same return-forward edges from the mapping
// primitives alone. Separate from the allocator set because the mechanism is:
// a wrapper over mmap costs page faults and TLB pressure, not arena
// contention, and FL070 grades the first while FL020 grades the second.
void inferMappingVocabulary(const ThreadRoleSummary &facts,
                            const std::vector<std::string> &extra,
                            std::set<std::string> &mappingsOut);

// Parameter positions carrying a thread identity, as "F|i". Seeded from every
// parameter of every thread entry, since that is what the spawn passed, then
// closed over the argument-flow edges.
void inferThreadIdentParams(const ThreadRoleSummary &facts,
                            std::set<std::string> &out);

// Acquire and release wrappers, closed over the strict forwarding edges from
// the POSIX primitives. The two sets are computed separately because FL012
// counts nesting depth: deriving the release side from the acquire spelling
// desynchronizes the count on the first wrapper that does not say "unlock".
//
// seededLock/seededUnlock report how many names came from the base case, so a
// caller can subtract them and say what this codebase contributed without
// hardcoding the seed count.
void inferLockVocabulary(const ThreadRoleSummary &facts,
                         const std::vector<std::string> &extraLock,
                         const std::vector<std::string> &extraUnlock,
                         std::set<std::string> &locksOut,
                         std::set<std::string> &unlocksOut,
                         size_t *seededLock = nullptr,
                         size_t *seededUnlock = nullptr);

// Wrappers whose verdict turned on a callee with no definition in this scan.
// Every site behind such a wrapper looks exactly like a clean result, so the
// boundary has to be named. Ordered by how many distinct callers the wrapper
// has, since that is what decides whether naming it is worth a config line.
std::vector<std::string> unresolvedVocabularyBoundaries(
    const ThreadRoleSummary &facts,
    const std::set<std::string> &allocators,
    const std::set<std::string> &freers);

// BFS role propagation over the merged call graph. "main" and mainPatterns
// seed ROLE_MAIN; threadEntries and entryPatterns seed ROLE_WORKER, both
// fnmatch globs against every known function name. Pure in its inputs.
//
// Function-pointer dispatch breaks the chain, which is what entryPatterns are
// for: an event-loop handler table has to name its worker roots in config.
ThreadRoleVerdicts computeThreadRoles(
    const ThreadRoleSummary &facts,
    const std::vector<std::string> &entryPatterns,
    const std::vector<std::string> &mainPatterns);

} // namespace lshaz
