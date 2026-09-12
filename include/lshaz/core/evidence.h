// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <string_view>
#include <vector>

namespace lshaz {

// Which hardware event confirms a rule. Every rule names a mechanism; this
// says what would have to be counted to see it.
//
// The family belongs with the rule, the event name does not: the counter a
// rule needs is spelled differently on every microarchitecture, so the
// operator supplies the name and this supplies what it has to measure.
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
