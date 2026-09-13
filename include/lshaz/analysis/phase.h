// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/analysis/thread_role.h"

#include <limits>
#include <set>
#include <string>

namespace lshaz {

// Which functions can only ever run before the program's first thread exists.
//
// Everything sequenced before pthread_create in the creating thread
// happens-before everything in the created thread (C11 7.26.5.6,
// [thread.thread.constr]). An access on the near side of that edge cannot be
// concurrent with any other access anywhere, so no second core holds the
// line: no RFO from a peer, no HITM, and the coherence cost is zero rather
// than small. That is a refutation, not a low estimate.
//
// Boolean lattice, monotone transfer, so the least fixed point is unique and
// shard arrival order cannot change it. Same determinism argument as
// points-to: not a controlled iteration order, but no other answer.
struct PhaseVerdicts {
    // Provably runs only before any thread is created. Membership is the
    // whole result; absence means concurrent or unanalysed, and those two
    // are deliberately the same answer here because both forbid refuting.
    std::set<std::string> preThread;

    // May create a thread before returning, directly or transitively.
    std::set<std::string> spawning;

    unsigned functionsSeen = 0;

    // Why the pre-thread window closes where it does. A thin partition looks
    // exactly like a program that spawns immediately, and the two need
    // different fixes, so the reason is output rather than inferred.
    std::string windowEnd;

    // An address-taken function that spawns, which is what makes every
    // indirect call a possible spawn point. Empty when none exists, and then
    // indirect calls are provably not spawn points.
    std::string indirectSpawnWitness;

    // No thread-creation call site anywhere, no main to start from, or a
    // global constructor spawns before main runs. Nothing is refuted then:
    // a codebase that spawns through an uncompiled library presents exactly
    // as one that never spawns, and refuting on that absence would be mass
    // recall loss rather than precision.
    bool dark = false;
    std::string darkReason;

    bool isPreThread(const std::string &fn) const {
        return !dark && preThread.count(fn) > 0;
    }

    // Every named function runs only before any thread exists. False when the
    // set is empty, since a claim about nobody is not a claim.
    bool allPreThread(const std::set<std::string> &fns) const {
        if (dark || fns.empty())
            return false;
        for (const auto &f : fns)
            if (!preThread.count(f))
                return false;
        return true;
    }

    std::set<std::string> concurrentSubset(
        const std::set<std::string> &fns) const {
        if (dark)
            return fns;
        std::set<std::string> out;
        for (const auto &f : fns)
            if (!preThread.count(f))
                out.insert(f);
        return out;
    }
};

// Solve both fixed points over the merged graph. Pure in its input, and
// testable with hand-written facts and no Clang at all, which is where the
// correctness argument lives.
PhaseVerdicts computePhases(const ThreadRoleSummary &facts);

} // namespace lshaz
