// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/cost.h"
#include "lshaz/core/severity.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <map>
#include <vector>

namespace clang {
class SourceLocation;
class SourceManager;
} // namespace clang

namespace lshaz {

enum class EvidenceTier : uint8_t {
    Proven,       // Structurally guaranteed from layout/IR (e.g., sizeof, field offset)
    Likely,       // Strong heuristic (e.g., escape analysis + atomic presence)
    Speculative,  // Topology-dependent or requires runtime confirmation
};

constexpr std::string_view evidenceTierName(EvidenceTier t) {
    switch (t) {
        case EvidenceTier::Proven:      return "proven";
        case EvidenceTier::Likely:      return "likely";
        case EvidenceTier::Speculative: return "speculative";
    }
    return "speculative";
}

constexpr bool operator<(EvidenceTier a, EvidenceTier b) {
    return static_cast<uint8_t>(a) < static_cast<uint8_t>(b);
}
constexpr bool operator>(EvidenceTier a, EvidenceTier b) {
    return static_cast<uint8_t>(a) > static_cast<uint8_t>(b);
}
constexpr bool operator<=(EvidenceTier a, EvidenceTier b) {
    return static_cast<uint8_t>(a) <= static_cast<uint8_t>(b);
}
constexpr bool operator>=(EvidenceTier a, EvidenceTier b) {
    return static_cast<uint8_t>(a) >= static_cast<uint8_t>(b);
}

struct SourceLocation {
    std::string file;
    unsigned line   = 0;
    unsigned column = 0;
};

SourceLocation resolveSourceLocation(clang::SourceLocation loc,
                                     const clang::SourceManager &SM);
                                     
// Whether a precondition was decided, and which way.
//
// Unknown and Refuted are different facts and must not share a slot. Nobody
// checked is the state a static pass leaves a condition it cannot see, and it
// has to stay recoverable: a later phase, a profile or a measurement may
// settle it. Checked and false is a verdict, and it retires the finding
// rather than lowering a score until some threshold elsewhere happens to
// delete it.
enum class ClaimState : uint8_t {
    Unknown = 0,      // not decided here; cannot promote, does not withdraw
    Established = 1,  // an observation confirmed the precondition
    Refuted = 2,      // an observation showed it does not hold
};

// Wire decoding. An out-of-range value from an older or newer peer reads as
// Unknown rather than inventing a verdict.
constexpr ClaimState toClaimState(int64_t v) {
    switch (v) {
        case 1:  return ClaimState::Established;
        case 2:  return ClaimState::Refuted;
        default: return ClaimState::Unknown;
    }
}

// A predicate a rule can decide from what it sees. False maps to Unknown and
// never to Refuted: not observing a condition is not disproving it, and only
// an evidence source that looked for absence may claim it.
constexpr ClaimState claimFrom(bool observed) {
    return observed ? ClaimState::Established : ClaimState::Unknown;
}

constexpr std::string_view claimStateName(ClaimState s) {
    switch (s) {
        case ClaimState::Unknown:     return "unknown";
        case ClaimState::Established: return "established";
        case ClaimState::Refuted:     return "refuted";
    }
    return "unknown";
}

struct MechanismClaim {
    std::string effect;        // what the hardware does
    std::string precondition;  // what must hold for it to happen
    ClaimState  state    = ClaimState::Unknown;
    Severity    supports = Severity::Informational;

    // Ordinary claims are alternatives: any one established mechanism can
    // carry the finding, so they combine with max. A gating claim is a
    // conjunct. Hotness is the example, since no mechanism costs anything
    // in code that never runs, so it caps the result whether or not it is
    // established. Combining a cap with max would silently do nothing.
    bool        gating   = false;

    // What settled it. Empty while Unknown; names the observation otherwise,
    // so a withdrawal can say what refuted it rather than reporting a number
    // that moved.
    std::string observation;
};

struct Diagnostic {
    std::string    ruleID;
    std::string    title;
    Severity       severity     = Severity::Informational;

    // How well this rule's own evidence ladder pins the finding down, in
    // [0,1]. A ranking prior, not a probability: it orders findings from one
    // rule, picks the survivor when several TUs saw a site with different
    // amounts of evidence, and breaks ties in the canonical order.
    //
    // Set once, by the rule that owns the ladder. Evidence arriving later is
    // a claim, not an addend, because adding one belief to another is not how
    // belief composes.
    double         confidence   = 0.0;
    EvidenceTier   evidenceTier = EvidenceTier::Speculative;
    bool           suppressed   = false; // Set by IR refiner when evidence contradicts AST
    SourceLocation location;
    std::string    functionName;         // Qualified name for IR correlation
    std::string    hardwareReasoning;
    std::map<std::string, std::string> structuralEvidence;
    std::string    mitigation;

    // Escalation trace: why severity was raised from base.
    std::vector<std::string> escalations;

    // HotnessSource as it stood in the emitting TU. Candidate means the TU
    // lacked the entry points to decide; the reduce phase resolves it
    // against the merged call graph and drops the finding if the function
    // is not globally hot. Stored untyped to keep this header free of the
    // oracle. Zero (None) for structural rules, which never consult it.
    uint8_t hotness = 0;

    // Mechanism claims, when the rule declares them. Empty means the rule
    // has not been migrated, which the invariant gate counts and reports
    // rather than silently passing.
    std::vector<MechanismClaim> mechanismClaims;

    // What the finding costs per unit of the target's work, as a product of
    // named terms. Empty for rules that cannot yet express their cost, which
    // then grade on structure exactly as before. A settled estimate enters
    // the ledger above as a gating claim, so it can retire a finding the
    // structure alone would have graded Critical, and cannot promote one on
    // terms that were guessed.
    CostEstimate cost;

    // Highest severity the established claims justify. Informational when
    // nothing is established; Critical when the rule declares nothing, so
    // an unmigrated rule is unconstrained rather than wrongly clamped.
    Severity severitySupportedByClaims() const {
        if (mechanismClaims.empty())
            return Severity::Critical;
        Severity best = Severity::Informational;
        Severity cap  = Severity::Critical;
        bool anyMechanism = false;
        for (const auto &c : mechanismClaims) {
            if (c.gating) {
                if (c.supports < cap) cap = c.supports;
                continue;
            }
            anyMechanism = true;
            if (c.state == ClaimState::Established && c.supports > best)
                best = c.supports;
        }
        // All-gating is a degenerate set: nothing asserted a mechanism, so
        // the cap is the whole statement rather than a bound on one.
        if (!anyMechanism) best = cap;
        return best < cap ? best : cap;
    }

    // Address a declared claim by the opening of its effect text, which is
    // how an evidence source names a condition it is qualified to decide
    // without knowing the rule that wrote it. Returns false when nothing
    // matches, so a caller can report a rule/evidence mismatch instead of
    // silently deciding nothing.
    bool settleClaim(std::string_view effectPrefix, ClaimState state,
                     std::string observation) {
        for (auto &c : mechanismClaims) {
            if (c.effect.compare(0, effectPrefix.size(), effectPrefix) != 0)
                continue;
            c.state = state;
            c.observation = std::move(observation);
            return true;
        }
        return false;
    }

    // Record a precondition an evidence source decided that no rule declared.
    // Gating, because a source only reaches for this when the condition it
    // checked is necessary for the mechanism to exist at all.
    void addSettledGate(std::string effect, std::string precondition,
                        ClaimState state, Severity supports,
                        std::string observation) {
        mechanismClaims.push_back({std::move(effect), std::move(precondition),
                                   state, supports, /*gating=*/true,
                                   std::move(observation)});
    }

    // The claim whose refutation retires this finding, or nullptr.
    //
    // A refuted gating claim is a necessary precondition known false, so the
    // mechanism cannot fire. Refuting every alternative does the same job
    // from the other side: the finding is left asserting no mechanism at all.
    // Either way the finding is withdrawn with a named cause, which is what
    // separates this from a score that drifted under a threshold.
    const MechanismClaim *refutedPrecondition() const {
        const MechanismClaim *lastOrdinary = nullptr;
        bool anyOrdinary = false, allOrdinaryRefuted = true;
        for (const auto &c : mechanismClaims) {
            if (c.gating) {
                if (c.state == ClaimState::Refuted) return &c;
                continue;
            }
            anyOrdinary = true;
            if (c.state == ClaimState::Refuted) lastOrdinary = &c;
            else allOrdinaryRefuted = false;
        }
        return (anyOrdinary && allOrdinaryRefuted) ? lastOrdinary : nullptr;
    }

    // Serialize structuralEvidence to "key=value; ..." for output/logging.
    std::string serializeEvidence() const;
};

// strict-weak content order for diagnostics whose location keys collide
// (macro-generated twins: one line, two symbols/types). every sort and
// dedup tiebreak must bottom out here or shard arrival order leaks into
// the output, std::sort is unstable.
bool diagnosticContentLess(const Diagnostic &a, const Diagnostic &b);

} // namespace lshaz
