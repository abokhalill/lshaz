// SPDX-License-Identifier: Apache-2.0
#include "lshaz/analysis/ThreadRoleSummary.h"

#include <fnmatch.h>

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

} // namespace lshaz
