// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string_view>
#include <vector>

namespace lshaz {

// Which hardware event confirms a rule.
//
// Every rule gets in here by naming a hardware mechanism, and until this
// table we could only ever check one of them. FL050 has graded on branch
// misprediction since the day it landed without anyone once holding it next
// to a branch-miss profile.
//
// The family belongs with the rule; the event name does not. Linux calls it
// branch-misses on this box and something else on the next one, so the
// operator names the event and this says what it has to measure.
enum class EvidenceFamily {
    None,            // structural claim, nothing to count at runtime
    Coherence,       // c2c gives us the richer per-line path
    BranchMispredict,
    DataTLB,
    InstructionTLB,
    CacheMiss,
    Cycles,          // fallback: did this cost anything at all
};

std::string_view evidenceFamilyName(EvidenceFamily f);
EvidenceFamily evidenceFamilyFromName(std::string_view name);

struct RuleEvidence {
    std::string_view id;
    EvidenceFamily family;

    // False when the cost lands somewhere other than the code that caused
    // it. An allocation is paid inside the allocator, so a quiet caller
    // refutes nothing and we must not score it as a miss.
    bool localised;

    std::string_view note;
};

const std::vector<RuleEvidence> &ruleEvidence();
const RuleEvidence *evidenceForRule(std::string_view id);

} // namespace lshaz
