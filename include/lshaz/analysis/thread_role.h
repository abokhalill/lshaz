// SPDX-License-Identifier: Apache-2.0
#pragma once

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

    // How the field is touched, not merely by whom. Counts are per-TU
    // partials and are summed in reduce; every threshold applies to the
    // total, because a per-TU verdict on how often a field is written would
    // depend on which shard happened to compile the writer.
    //
    // standing versus handed is the distinction that makes a single-field
    // contention rule possible at all. A write reaching a fixed object by
    // name is shared state every thread addresses directly; a write to
    // whatever the caller passed in moves with the object and contends with
    // nothing. Writer counts cannot separate them, and the per-TU view
    // cannot either: one TU seeing one writer has no way to know whether the
    // other TU's writer reaches the same instance.
    struct FieldAccessFacts {
        unsigned writeSites = 0;
        unsigned loopWriteSites = 0;
        unsigned standingWriteSites = 0;
        unsigned handedWriteSites = 0;
        unsigned readSites = 0;

        void merge(const FieldAccessFacts &o) {
            writeSites += o.writeSites;
            loopWriteSites += o.loopWriteSites;
            standingWriteSites += o.standingWriteSites;
            handedWriteSites += o.handedWriteSites;
            readSites += o.readSites;
        }
        bool empty() const {
            return writeSites == 0 && readSites == 0;
        }
        // A fixed object the program names, rather than one handed in. Ties
        // go to handed: an even split is a type used both ways, and calling
        // that standing would fire on every per-request struct.
        bool standing() const {
            return standingWriteSites > handedWriteSites;
        }
    };
    std::map<std::string, FieldAccessFacts> fieldAccess;

    // Loop nesting at each call site, and each function's own maximum loop
    // depth. Hotness inference is loop-depth-weighted, so the reduce phase
    // needs both to rerun the per-TU relaxation over the merged graph rather
    // than degrading every cross-TU callee to the weakest grade.
    std::map<std::string, std::map<std::string, unsigned>> edgeLoopDepth;
    std::map<std::string, unsigned> ownLoopDepth;

    // Functions that allocate, and functions that free, a block of a given
    // pointee type. The join key is the type name because it is the only
    // thing that crosses a TU boundary: the allocation and the free that
    // releases it routinely sit in different files, and no pointer value
    // survives the split. A site whose type cannot be named is left out,
    // which leaves FL020's conjunct unestablished rather than guessed.
    std::map<std::string, std::set<std::string>> allocatorsOfType;
    std::map<std::string, std::set<std::string>> freersOfType;

    // Raw structure for inferring the project's own allocator vocabulary,
    // rather than being told it. Requiring a human to declare zmalloc,
    // ngx_palloc, palloc, xmalloc or kmalloc before the rule can see anything
    // is hardcoding with a config file in front of it, and it has to be
    // rediscovered per codebase.
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

    // Seeds taken from the declaration rather than its spelling. A libc name
    // list is defeated by one #define: redis builds jemalloc with
    // "#define malloc(size) je_malloc(size)", so no seed name survives
    // preprocessing anywhere in the tree. The attributes do survive, and an
    // allocator carries them because the optimizer needs them, which is what
    // makes this a seed rule no name list has to keep up with.
    //
    // Produced only by the vocabulary prepass, which runs in the parent, so
    // these never cross the IPC boundary.
    std::set<std::string> declaredAllocators;
    std::set<std::string> declaredFreers;
    std::set<std::string> declaredLocks;
    std::set<std::string> declaredUnlocks;

    // A spin lock has no POSIX call and no attribute to find it by: nginx's
    // ngx_shmtx_lock reaches the mutex through __sync_bool_compare_and_swap
    // and nothing else. What it does have is a mechanism, which is the bar a
    // rule is held to here. An acquire is an atomic read-modify-write whose
    // loop exits when it succeeds; the release is the same RMW with no loop
    // around it.
    //
    // Keyed by the parameter's pointee type so the two sides can be paired.
    // Pairing is what separates a lock from a lock-free retry loop, which
    // executes the identical CAS: a queue push has no release counterpart
    // taking the same type, and counting one as an acquire would leave
    // FL012's nesting depth permanently raised.
    std::map<std::string, std::set<std::string>> spinAcquireOfType;
    std::map<std::string, std::set<std::string>> spinReleaseOfType;

    // Types an atomic read-modify-write was performed on. A codebase wrapping
    // its atomics in a plain typedef (atomic_t, spinlock_t, ngx_atomic_t) has
    // no _Atomic and no std::atomic anywhere, so the fields simply do not
    // exist as far as atomic detection is concerned, and the false-sharing
    // rules read them as ordinary members. Being the operand of a lock-prefixed
    // RMW is what makes a type atomic; the spelling never was.
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
    // to a method absent here is monomorphic program-wide, which is the
    // difference between paying ~1ns and ~9ns. Only the merged set can say,
    // the override usually lives in another TU than the call.
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

    // Union of roles over the attributed members, ignoring the rest.
    //
    // rolesOf answers "can this set be proven disjoint from another", and
    // there one unattributed member has to poison the answer. "Does this set
    // reach more than one role" is the opposite question: an unattributed
    // member can only add a role, never remove one, so the attributed subset
    // is a sound lower bound and refusing to answer from it discards
    // evidence rather than being careful with it.
    //
    // The difference is not academic. A field read from a hundred functions
    // has essentially no chance of every one being attributed, so the strict
    // form reports ROLE_NONE for exactly the widely-shared fields a
    // contention rule exists to find. server.unixtime, the largest measured
    // contended line in redis, failed on this and on nothing else.
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
// recorded call sites into allocatorsOfType / freersOfType. Seeds are the libc
// primitives only, so a project's own names are derived rather than declared.
// extraAlloc / extraFree add configured patterns for the cases structure
// cannot reach: an allocator whose result leaves through an out-parameter, or
// one whose body this scan never saw.
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

// Acquire and release wrappers, closed over the strict forwarding edges from
// the POSIX primitives. The two sets are computed separately because FL012
// counts nesting depth: deriving the release side from the acquire spelling
// desynchronizes the count on the first wrapper that does not say "unlock".
// seededLock/seededUnlock report how many names came from the base case, so a
// caller can say what this codebase contributed. Counting that in the reporter
// meant a magic number there, and expanding the seed list silently turned it
// into a claim of eleven derived names when none were.
// Parameter positions carrying a thread identity, as "F|i". Seeded from every
// parameter of every thread entry, since that is what the spawn passed, then
// closed over the argument-flow edges.
void inferThreadIdentParams(const ThreadRoleSummary &facts,
                            std::set<std::string> &out);

void inferLockVocabulary(const ThreadRoleSummary &facts,
                         const std::vector<std::string> &extraLock,
                         const std::vector<std::string> &extraUnlock,
                         std::set<std::string> &locksOut,
                         std::set<std::string> &unlocksOut,
                         size_t *seededLock = nullptr,
                         size_t *seededUnlock = nullptr);

// Wrappers whose verdict turned on a callee with no definition in this scan.
// redis reaches je_free_with_usize this way, and the 236 zfree sites behind
// it look exactly like a clean result. Ordered by how many distinct callers
// the wrapper has, since that is what decides whether naming it is worth a
// config line.
std::vector<std::string> unresolvedVocabularyBoundaries(
    const ThreadRoleSummary &facts,
    const std::set<std::string> &allocators,
    const std::set<std::string> &freers);

// BFS role propagation over the merged call graph. Roots: "main" (plus
// mainPatterns matches) seed ROLE_MAIN; threadEntries (plus entryPatterns
// matches, fnmatch globs against every known function name) seed
// ROLE_WORKER. Pure function of its inputs.
//
// Known limitation: Function-pointer dispatch (event-loop handler tables) breaks
// the chain; entryPatterns exist so codebases like that can name their
// worker roots explicitly in config.
ThreadRoleVerdicts computeThreadRoles(
    const ThreadRoleSummary &facts,
    const std::vector<std::string> &entryPatterns,
    const std::vector<std::string> &mainPatterns);

} // namespace lshaz
