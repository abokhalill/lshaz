// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/Diagnostic.h"

#include <algorithm>
#include <sstream>

namespace lshaz {

std::string Diagnostic::serializeEvidence() const {
    // Sort keys for deterministic output.
    std::vector<std::string> keys;
    keys.reserve(structuralEvidence.size());
    for (const auto &[k, _] : structuralEvidence)
        keys.push_back(k);
    std::sort(keys.begin(), keys.end());

    std::ostringstream os;
    bool first = true;
    for (const auto &k : keys) {
        if (!first) os << "; ";
        os << k << "=" << structuralEvidence.at(k);
        first = false;
    }
    return os.str();
}



bool diagnosticContentLess(const Diagnostic &a, const Diagnostic &b) {
    if (a.severity != b.severity)
        return static_cast<uint8_t>(a.severity) < static_cast<uint8_t>(b.severity);
    if (a.confidence != b.confidence)
        return a.confidence < b.confidence;
    if (a.evidenceTier != b.evidenceTier)
        return static_cast<uint8_t>(a.evidenceTier) <
               static_cast<uint8_t>(b.evidenceTier);
    if (a.functionName != b.functionName)
        return a.functionName < b.functionName;
    if (a.title != b.title)
        return a.title < b.title;
    if (a.structuralEvidence != b.structuralEvidence)
        return a.structuralEvidence < b.structuralEvidence;
    if (a.escalations != b.escalations)
        return a.escalations < b.escalations;
    return a.mitigation < b.mitigation;
}
} // namespace lshaz
