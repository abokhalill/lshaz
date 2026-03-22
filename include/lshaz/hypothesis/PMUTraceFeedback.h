// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/hypothesis/CalibrationFeedback.h"
#include "lshaz/hypothesis/HazardClass.h"
#include "lshaz/hypothesis/PMUCounter.h"

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace lshaz {

struct PMUSample {
    std::string counterName;
    uint64_t value = 0;
    uint64_t duration_ns = 0;
};

struct PMUTraceRecord {
    std::string functionName;
    std::string sourceFile;
    unsigned sourceLine = 0;

    std::vector<PMUSample> samples;

    std::string cpuModel;
    std::string skuFamily;
    uint64_t timestampEpochSec = 0;

    std::string findingId;
};

struct HazardPrior {
    HazardClass hazardClass;
    double priorConfidence = 0.5;
    double falsePositiveRate = 0.0;
    double truePositiveRate = 0.0;
    uint32_t totalObservations = 0;
    uint32_t confirmedHazards = 0;
    uint32_t refutedHazards = 0;
};

/* Above confirm → positive, below refute → negative, between → inconclusive. */
struct CounterThreshold {
    std::string counterName;
    double confirmThreshold = 0.0;
    double refuteThreshold = 0.0;
};

/*
 * Closed-loop PMU feedback: ingests production counter data,
 * updates Bayesian priors per hazard class, feeds labeled
 * records into CalibrationFeedbackStore.
 */
class PMUTraceFeedbackLoop {
public:
    explicit PMUTraceFeedbackLoop(CalibrationFeedbackStore &calStore);

    LabelValue ingestTrace(const PMUTraceRecord &trace,
                           HazardClass hazardClass,
                           const std::vector<double> &featureVector);

    const HazardPrior *getPrior(HazardClass hc) const;
    const std::unordered_map<std::string, HazardPrior> &allPriors() const {
        return priors_;
    }

    double adjustConfidence(double baseConfidence, HazardClass hc) const;
    bool savePriors(const std::string &path) const;
    bool loadPriors(const std::string &path);

private:
    static std::vector<CounterThreshold> defaultThresholds(HazardClass hc);
    LabelValue evaluateCounters(const std::vector<PMUSample> &samples,
                                 HazardClass hc) const;

    void updatePrior(HazardClass hc, LabelValue verdict);

    CalibrationFeedbackStore &calStore_;
    std::unordered_map<std::string, HazardPrior> priors_; /* keyed by hazardClassName */
};

} // namespace lshaz
