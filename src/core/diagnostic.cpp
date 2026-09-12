// SPDX-License-Identifier: Apache-2.0
#include "lshaz/core/diagnostic.h"

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
    if (a.mitigation != b.mitigation)
        return a.mitigation < b.mitigation;
    // Every sort has to bottom out here or shard arrival order leaks into the
    // output. These three were missing, so two diagnostics differing only in
    // their reasoning, hotness grade or claim set compared equal and std::sort
    // left them in the order the shards happened to return. Reachability was
    // never the argument: an invariant nothing enforces is one that stops
    // holding without anyone noticing.
    if (a.hardwareReasoning != b.hardwareReasoning)
        return a.hardwareReasoning < b.hardwareReasoning;
    if (a.hotness != b.hotness)
        return a.hotness < b.hotness;
    if (a.mechanismClaims.size() != b.mechanismClaims.size())
        return a.mechanismClaims.size() < b.mechanismClaims.size();
    for (size_t i = 0; i < a.mechanismClaims.size(); ++i) {
        const auto &x = a.mechanismClaims[i], &y = b.mechanismClaims[i];
        if (x.supports != y.supports)
            return static_cast<uint8_t>(x.supports) <
                   static_cast<uint8_t>(y.supports);
        if (x.state != y.state)
            return static_cast<uint8_t>(x.state) < static_cast<uint8_t>(y.state);
        if (x.gating != y.gating)           return x.gating < y.gating;
        if (x.effect != y.effect)           return x.effect < y.effect;
        if (x.precondition != y.precondition)
            return x.precondition < y.precondition;
    }
    return false;
}
} // namespace lshaz
