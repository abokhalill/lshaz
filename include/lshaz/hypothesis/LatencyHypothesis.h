// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/hypothesis/EvidenceTier.h"
#include "lshaz/hypothesis/HazardClass.h"
#include "lshaz/hypothesis/PMUCounter.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace lshaz {

struct MetricSpec {
    std::string name;        // e.g., "p99.9_operation_latency_ns"
    std::string unit;        // e.g., "nanoseconds"
    std::string percentile;  // e.g., "p99.9"
};

struct ConfoundControl {
    std::string variable;    // e.g., "cpu_frequency"
    std::string method;      // e.g., "cpupower frequency-set --governor performance"
};

enum class ExperimentVerdict : uint8_t {
    Pending,
    Confirmed,     // H0 rejected at alpha with sufficient power
    Refuted,       // H0 not rejected
    Inconclusive,  // Insufficient power or excessive variance
    Confounded,    // Uncontrolled variable invalidated experiment
};

constexpr std::string_view verdictName(ExperimentVerdict v) {
    switch (v) {
        case ExperimentVerdict::Pending:      return "pending";
        case ExperimentVerdict::Confirmed:    return "confirmed";
        case ExperimentVerdict::Refuted:      return "refuted";
        case ExperimentVerdict::Inconclusive: return "inconclusive";
        case ExperimentVerdict::Confounded:   return "confounded";
    }
    return "unknown";
}

struct LatencyHypothesis {
    std::string findingId;
    std::string hypothesisId;
    HazardClass hazardClass;

    std::string H0;
    std::string H1;

    MetricSpec primaryMetric;
    PMUCounterSet counterSet;

    double minimumDetectableEffect = 0.05; // 5% relative increase
    double significanceLevel       = 0.01; // alpha
    double power                   = 0.90; // 1 - beta
    uint32_t requiredRuns          = 0;    // 0 = compute from pilot

    std::string controlDescription;
    std::string treatmentDescription;

    std::vector<ConfoundControl> confoundControls;
    std::vector<double> structuralFeatures;
    std::map<std::string, std::string> structuralEvidence;
    EvidenceTier evidenceTier = EvidenceTier::Speculative;

    ExperimentVerdict verdict = ExperimentVerdict::Pending;
};

} // namespace lshaz
