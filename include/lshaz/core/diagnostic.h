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
                                     
struct MechanismClaim {
    std::string effect;        // what the hardware does
    std::string precondition;  // what must hold for it to happen
    bool        established = false;
    Severity    supports    = Severity::Informational;

    // Ordinary claims are alternatives: any one established mechanism can
    // carry the finding, so they combine with max. A gating claim is a
    // conjunct. Hotness is the example, since no mechanism costs anything
    // in code that never runs, so it caps the result whether or not it is
    // established. Combining a cap with max would silently do nothing.
    bool        gating      = false;
};

struct Diagnostic {
    std::string    ruleID;
    std::string    title;
    Severity       severity     = Severity::Informational;
    double         confidence   = 0.0; // [0.0, 1.0]
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
            if (c.established && c.supports > best) best = c.supports;
        }
        // All-gating is a degenerate set: nothing asserted a mechanism, so
        // the cap is the whole statement rather than a bound on one.
        if (!anyMechanism) best = cap;
        return best < cap ? best : cap;
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
