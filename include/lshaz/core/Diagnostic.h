// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/Severity.h"

#include <cstdint>
#include <string>
#include <string_view>
#include <map>
#include <vector>

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

    // Serialize structuralEvidence to "key=value; ..." for output/logging.
    std::string serializeEvidence() const;
};

} // namespace lshaz
