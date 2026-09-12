// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/thread_role.h"

#include <fnmatch.h>

#include <algorithm>
#include <deque>

namespace lshaz {

namespace {

void propagate(const ThreadRoleSummary &facts,
               const std::set<std::string> &roots,
               uint8_t role,
               std::map<std::string, uint8_t> &out) {
    std::deque<std::string> work(roots.begin(), roots.end());
    while (!work.empty()) {
        std::string fn = std::move(work.front());
        work.pop_front();
        uint8_t &mask = out[fn];
        if (mask & role)
            continue;
        mask |= role;
        auto it = facts.callEdges.find(fn);
        if (it == facts.callEdges.end())
            continue;
        for (const auto &callee : it->second)
            work.push_back(callee);
    }
}

bool matchesAny(const std::string &name,
                const std::vector<std::string> &patterns) {
    for (const auto &p : patterns)
        if (fnmatch(p.c_str(), name.c_str(), 0) == 0)
            return true;
    return false;
}

} // anonymous namespace

ThreadRoleVerdicts computeThreadRoles(
    const ThreadRoleSummary &facts,
    const std::vector<std::string> &entryPatterns,
    const std::vector<std::string> &mainPatterns) {

    // The universe of known function names: everything that appears as a
    // caller, a callee, or a field writer. Pattern roots are matched
    // against this set so a glob can only name functions we can reason
    // about.
    std::set<std::string> universe;
    for (const auto &[caller, callees] : facts.callEdges) {
        universe.insert(caller);
        universe.insert(callees.begin(), callees.end());
    }
    for (const auto &[field, writers] : facts.fieldWriters)
        universe.insert(writers.begin(), writers.end());

    std::set<std::string> mainRoots;
    if (universe.count("main"))
        mainRoots.insert("main");
    std::set<std::string> workerRoots = facts.threadEntries;

    if (!entryPatterns.empty() || !mainPatterns.empty()) {
        for (const auto &fn : universe) {
            if (matchesAny(fn, entryPatterns))
                workerRoots.insert(fn);
            if (matchesAny(fn, mainPatterns))
                mainRoots.insert(fn);
        }
    }

    ThreadRoleVerdicts v;
    if (workerRoots.empty())
        return v; // single-threaded program: no attribution to make

    propagate(facts, mainRoots, ROLE_MAIN, v.functionRoles);
    propagate(facts, workerRoots, ROLE_WORKER, v.functionRoles);
    return v;
}


namespace {

// libc, plus the C++ operators Clang spells this way. These are ABI, not a
// codebase's vocabulary, so seeding from them does not fix the analysis to
// any project.
const char *kAllocSeeds[] = {
    "malloc", "calloc", "realloc", "aligned_alloc", "posix_memalign",
    "valloc", "pvalloc", "memalign", "strdup", "strndup", "mmap", "mmap64",
    "operator new", "operator new[]",
};
// The release side needs names where the allocation side does not: alloc_size
// covers jemalloc, tcmalloc and mimalloc alike, and no deallocation attribute
// is used in practice, so a free chain ending in a replacement allocator's ABI
// terminates at a bare extern carrying no evidence. These are published
// third-party ABIs, on the same footing as libc, and never a scanned
// project's own vocabulary.
const char *kFreeSeeds[] = {
    "free", "cfree", "munmap", "operator delete", "operator delete[]",
    "dallocx", "sdallocx", "je_dallocx", "je_sdallocx", "je_free",
    "tc_free", "tc_cfree", "tc_delete",
    "mi_free", "mi_free_size", "mi_free_aligned",
};

// Least fixpoint over edges: a function joins the set once any callee it
// forwards to is in it. Monotone and finite, so iteration terminates; the
// bound is the edge count, which is why the worklist is a plain loop.
void closeOver(const std::map<std::string, std::set<std::string>> &edges,
               std::set<std::string> &set) {
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto &[fn, callees] : edges) {
            if (set.count(fn))
                continue;
            for (const auto &c : callees)
                if (set.count(c)) {
                    set.insert(fn);
                    changed = true;
                    break;
                }
        }
    }
}

} // namespace

void inferAllocatorVocabulary(ThreadRoleSummary &facts,
                              const std::vector<std::string> &extraAlloc,
                              std::set<std::string> &allocatorsOut,
                              std::set<std::string> &freersOut) {
    for (const char *s : kAllocSeeds) allocatorsOut.insert(s);
    for (const char *s : kFreeSeeds)  freersOut.insert(s);
    allocatorsOut.insert(facts.declaredAllocators.begin(),
                         facts.declaredAllocators.end());
    freersOut.insert(facts.declaredFreers.begin(),
                     facts.declaredFreers.end());

    // Configured patterns join the seed set rather than replacing inference:
    // they are for allocators whose structure this cannot see, not for the
    // ordinary wrapper.
    if (!extraAlloc.empty()) {
        std::set<std::string> known;
        for (const auto &[f, _] : facts.returnForwards) known.insert(f);
        for (const auto &[f, _] : facts.paramForwards)  known.insert(f);
        for (const auto &[g, _] : facts.allocSitesByCallee) known.insert(g);
        for (const auto &[g, _] : facts.freeSitesByCallee)  known.insert(g);
        for (const auto &pat : extraAlloc)
            for (const auto &fn : known)
                if (fnmatch(pat.c_str(), fn.c_str(), 0) == 0) {
                    allocatorsOut.insert(fn);
                    freersOut.insert(fn);
                }
    }

    closeOver(facts.returnForwards, allocatorsOut);
    closeOver(facts.paramForwards, freersOut);

    // "F|T" splits back into the function that owns the site and the type it
    // handled. Only now is it known whether the callee allocates.
    auto attribute =
        [](const std::map<std::string, std::set<std::string>> &sites,
           const std::set<std::string> &vocab,
           std::map<std::string, std::set<std::string>> &out) {
            for (const auto &[callee, entries] : sites) {
                if (!vocab.count(callee))
                    continue;
                for (const auto &e : entries) {
                    auto bar = e.find('|');
                    if (bar == std::string::npos || bar + 1 >= e.size())
                        continue;
                    out[e.substr(bar + 1)].insert(e.substr(0, bar));
                }
            }
        };
    attribute(facts.allocSitesByCallee, allocatorsOut, facts.allocatorsOfType);
    attribute(facts.freeSitesByCallee, freersOut, facts.freersOfType);
}

void inferThreadIdentParams(const ThreadRoleSummary &facts,
                            std::set<std::string> &out) {
    for (const auto &e : facts.threadEntries)
        for (unsigned i = 0; i < 8; ++i)
            out.insert(e + "|" + std::to_string(i));

    // "F|i|G|j" joins when F|i is already an identity, adding G|j. Monotone
    // over a finite set, so the loop settles.
    bool changed = true;
    while (changed) {
        changed = false;
        for (const auto &edge : facts.identArgFlow) {
            auto p1 = edge.find('|');
            if (p1 == std::string::npos) continue;
            auto p2 = edge.find('|', p1 + 1);
            if (p2 == std::string::npos) continue;
            auto p3 = edge.rfind('|');
            if (p3 == p2 || p3 == std::string::npos) continue;
            std::string src = edge.substr(0, p2);
            std::string dst = edge.substr(p2 + 1, p3 - p2 - 1) + "|" +
                              edge.substr(p3 + 1);
            if (out.count(src) && !out.count(dst)) {
                out.insert(dst);
                changed = true;
            }
        }
    }
}

void inferMappingVocabulary(const ThreadRoleSummary &facts,
                            const std::vector<std::string> &extra,
                            std::set<std::string> &mappingsOut) {
    // Kernel-facing mapping calls. ABI, like the libc allocator seeds.
    for (const char *s : {"mmap", "mmap64", "mremap", "shmat"})
        mappingsOut.insert(s);
    if (!extra.empty()) {
        std::set<std::string> known;
        for (const auto &[f, _] : facts.returnForwards) known.insert(f);
        for (const auto &pat : extra)
            for (const auto &fn : known)
                if (fnmatch(pat.c_str(), fn.c_str(), 0) == 0)
                    mappingsOut.insert(fn);
    }
    closeOver(facts.returnForwards, mappingsOut);
}

void inferLockVocabulary(const ThreadRoleSummary &facts,
                         const std::vector<std::string> &extraLock,
                         const std::vector<std::string> &extraUnlock,
                         std::set<std::string> &locksOut,
                         std::set<std::string> &unlocksOut,
                         size_t *seededLock,
                         size_t *seededUnlock) {
    // POSIX and C11, on the same footing as the libc allocator seeds: frozen
    // by the standards and never a user's vocabulary. The base case the
    // fixpoint needs, since "F forwards a parameter to G" has to terminate.
    // Unlike allocation there is no attribute the toolchain synthesizes here,
    // so the standard acquire API is the one vocabulary that cannot be
    // derived.
    //
    // A codebase whose locks are none of these is still reached: by the
    // capability attributes if it annotates, and by acquire/release pairing
    // on an atomic RMW if it rolls its own.
    for (const char *s : {"pthread_mutex_lock", "pthread_mutex_trylock",
                          "pthread_mutex_timedlock", "pthread_spin_lock",
                          "pthread_spin_trylock", "pthread_rwlock_rdlock",
                          "pthread_rwlock_wrlock", "pthread_rwlock_tryrdlock",
                          "pthread_rwlock_trywrlock",
                          "pthread_rwlock_timedrdlock",
                          "pthread_rwlock_timedwrlock",
                          "pthread_cond_wait", "pthread_cond_timedwait",
                          "pthread_barrier_wait",
                          "sem_wait", "sem_trywait", "sem_timedwait",
                          "mtx_lock", "mtx_trylock", "mtx_timedlock",
                          "cnd_wait", "cnd_timedwait"})
        locksOut.insert(s);
    for (const char *s : {"pthread_mutex_unlock", "pthread_spin_unlock",
                          "pthread_rwlock_unlock", "sem_post",
                          "mtx_unlock", "cnd_signal", "cnd_broadcast",
                          "pthread_cond_signal", "pthread_cond_broadcast"})
        unlocksOut.insert(s);
    if (seededLock) *seededLock = locksOut.size();
    if (seededUnlock) *seededUnlock = unlocksOut.size();
    locksOut.insert(facts.declaredLocks.begin(), facts.declaredLocks.end());
    unlocksOut.insert(facts.declaredUnlocks.begin(),
                      facts.declaredUnlocks.end());

    std::set<std::string> known;
    for (const auto &[f, _] : facts.strictParamForwards) known.insert(f);
    auto seed = [&](const std::vector<std::string> &pats,
                    std::set<std::string> &dst) {
        for (const auto &p : pats)
            for (const auto &fn : known)
                if (fnmatch(p.c_str(), fn.c_str(), 0) == 0)
                    dst.insert(fn);
    };
    seed(extraLock, locksOut);
    seed(extraUnlock, unlocksOut);

    // Spin locks, paired by the type both sides operate on. A CAS retry loop
    // with no release counterpart taking the same type is a lock-free
    // operation, not an acquire, and is left out.
    for (const auto &[type, acquirers] : facts.spinAcquireOfType) {
        auto rel = facts.spinReleaseOfType.find(type);
        if (rel == facts.spinReleaseOfType.end())
            continue;
        for (const auto &f : acquirers)
            if (!rel->second.count(f))
                locksOut.insert(f);
        for (const auto &f : rel->second)
            if (!acquirers.count(f))
                unlocksOut.insert(f);
    }

    closeOver(facts.strictParamForwards, locksOut);
    closeOver(facts.strictParamForwards, unlocksOut);

    // A wrapper that forwards to both sides is a critical section, not an
    // acquire. Counting it as one leaves FL012's nesting depth permanently
    // raised for every caller after it.
    for (auto it = locksOut.begin(); it != locksOut.end();)
        it = unlocksOut.count(*it) ? locksOut.erase(it) : std::next(it);
}

std::vector<std::string> unresolvedVocabularyBoundaries(
    const ThreadRoleSummary &facts,
    const std::set<std::string> &allocators,
    const std::set<std::string> &freers) {

    std::set<std::string> out;
    auto scan = [&](const std::map<std::string, std::set<std::string>> &edges,
                    const std::set<std::string> &decided) {
        for (const auto &[fn, callees] : edges) {
            if (decided.count(fn))
                continue;
            for (const auto &c : callees)
                if (!facts.definedFunctions.count(c) &&
                    !facts.builtinCallees.count(c)) {
                    out.insert(fn);
                    break;
                }
        }
    };
    scan(facts.returnForwards, allocators);
    scan(facts.paramForwards, freers);

    // Sites recorded against the name, which is what the undecided verdict
    // actually costs. callEdges would be the obvious weight and is empty here:
    // the prepass collects ownership only, and the call graph is built in the
    // pass after it.
    auto weight = [&](const std::string &n) {
        size_t w = 0;
        if (auto it = facts.allocSitesByCallee.find(n);
            it != facts.allocSitesByCallee.end())
            w += it->second.size();
        if (auto it = facts.freeSitesByCallee.find(n);
            it != facts.freeSitesByCallee.end())
            w += it->second.size();
        return w;
    };
    std::vector<std::string> ranked(out.begin(), out.end());
    std::sort(ranked.begin(), ranked.end(),
              [&](const std::string &a, const std::string &b) {
                  size_t wa = weight(a), wb = weight(b);
                  return wa != wb ? wa > wb : a < b;
              });
    return ranked;
}


} // namespace lshaz
