// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/PMUTraceFeedback.h"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <sstream>

namespace lshaz {

PMUTraceFeedbackLoop::PMUTraceFeedbackLoop(CalibrationFeedbackStore &calStore)
    : calStore_(calStore) {
    auto initPrior = [&](HazardClass hc) {
        HazardPrior p;
        p.hazardClass = hc;
        p.priorConfidence = 0.5;
        priors_[std::string(hazardClassName(hc))] = p;
    };

    initPrior(HazardClass::CacheGeometry);
    initPrior(HazardClass::FalseSharing);
    initPrior(HazardClass::AtomicOrdering);
    initPrior(HazardClass::AtomicContention);
    initPrior(HazardClass::LockContention);
    initPrior(HazardClass::HeapAllocation);
    initPrior(HazardClass::StackPressure);
    initPrior(HazardClass::VirtualDispatch);
    initPrior(HazardClass::StdFunction);
    initPrior(HazardClass::GlobalState);
    initPrior(HazardClass::ContendedQueue);
    initPrior(HazardClass::DeepConditional);
    initPrior(HazardClass::NUMALocality);
    initPrior(HazardClass::CentralizedDispatch);
    initPrior(HazardClass::HazardAmplification);
}

LabelValue PMUTraceFeedbackLoop::ingestTrace(
    const PMUTraceRecord &trace,
    HazardClass hazardClass,
    const std::vector<double> &featureVector) {

    LabelValue verdict = evaluateCounters(trace.samples, hazardClass);

    updatePrior(hazardClass, verdict);
    ExperimentResult expResult;
    expResult.findingId = trace.findingId.empty()
        ? (trace.functionName + ":" + std::to_string(trace.sourceLine))
        : trace.findingId;
    expResult.hypothesisId = "PMU-" + std::string(hazardClassName(hazardClass));
    expResult.schemaVersion = "1.0.0";
    expResult.ingestionTimestamp = trace.timestampEpochSec;
    expResult.envState.cpuModel = trace.cpuModel.empty()
        ? "unknown" : trace.cpuModel;
    expResult.envState.skuFamily = trace.skuFamily;
    expResult.warmupIterations = 1;  /* validateSchema invariant */
    expResult.measurementIterations = 1;
    for (const auto &sample : trace.samples) {
        CounterDelta cd;
        cd.counterName = sample.counterName;
        cd.treatment = sample.value;
        cd.control = 0;
        expResult.counterDeltas.push_back(cd);
    }

    switch (verdict) {
        case LabelValue::Positive:
            expResult.verdict = ExperimentVerdict::Confirmed;
            expResult.effectSizeD = 0.8;
            expResult.pValue = 0.01;
            break;
        case LabelValue::Negative:
            expResult.verdict = ExperimentVerdict::Refuted;
            expResult.effectSizeD = 0.1;
            expResult.pValue = 0.5;
            break;
        default:
            expResult.verdict = ExperimentVerdict::Inconclusive;
            expResult.effectSizeD = 0.3;
            expResult.pValue = 0.2;
            break;
    }

    calStore_.ingest(expResult, featureVector, hazardClass);

    if (verdict == LabelValue::Negative) {
        calStore_.registerFalsePositive(
            featureVector, hazardClass,
            "Refuted by production PMU trace at " + expResult.findingId);
    }

    return verdict;
}

const HazardPrior *PMUTraceFeedbackLoop::getPrior(HazardClass hc) const {
    auto it = priors_.find(std::string(hazardClassName(hc)));
    return it != priors_.end() ? &it->second : nullptr;
}

double PMUTraceFeedbackLoop::adjustConfidence(double baseConfidence,
                                               HazardClass hc) const {
    const auto *prior = getPrior(hc);
    if (!prior || prior->totalObservations == 0)
        return baseConfidence;

    /* Bayesian blend: production data weight saturates at 50 observations. */
    double obsWeight = std::min(1.0,
        static_cast<double>(prior->totalObservations) / 50.0);
    double adjusted = baseConfidence * (1.0 - obsWeight) +
                      prior->priorConfidence * obsWeight;

    return std::clamp(adjusted, 0.05, 0.99);
}

bool PMUTraceFeedbackLoop::savePriors(const std::string &path) const {
    std::ofstream out(path);
    if (!out.is_open())
        return false;

    std::vector<std::string> keys; /* sorted for deterministic output */
    keys.reserve(priors_.size());
    for (const auto &[name, _] : priors_)
        keys.push_back(name);
    std::sort(keys.begin(), keys.end());

    out << "# lshaz PMU trace priors v1\n";
    for (const auto &name : keys) {
        const auto &prior = priors_.at(name);
        out << name
            << " " << prior.priorConfidence
            << " " << prior.falsePositiveRate
            << " " << prior.truePositiveRate
            << " " << prior.totalObservations
            << " " << prior.confirmedHazards
            << " " << prior.refutedHazards
            << "\n";
    }
    return out.good();
}

bool PMUTraceFeedbackLoop::loadPriors(const std::string &path) {
    std::ifstream in(path);
    if (!in.is_open())
        return false;

    std::string line;
    while (std::getline(in, line)) {
        if (line.empty() || line[0] == '#')
            continue;

        std::istringstream iss(line);
        std::string name;
        HazardPrior p;
        if (!(iss >> name >> p.priorConfidence >> p.falsePositiveRate
                  >> p.truePositiveRate >> p.totalObservations
                  >> p.confirmedHazards >> p.refutedHazards))
            continue;

        // Preserve hazardClass from existing prior if available.
        auto it = priors_.find(name);
        if (it != priors_.end())
            p.hazardClass = it->second.hazardClass;

        priors_[name] = p;
    }
    return true;
}

std::vector<CounterThreshold> PMUTraceFeedbackLoop::defaultThresholds(
    HazardClass hc) {

    /* Per-second thresholds, x86-64 server workloads. */
    switch (hc) {
        case HazardClass::CacheGeometry:
        case HazardClass::FalseSharing:
            return {
                {"MEM_LOAD_RETIRED.L3_MISS", 10000, 100},
                {"OFFCORE_RESPONSE.DEMAND_DATA_RD.L3_MISS", 5000, 50},
            };
        case HazardClass::AtomicOrdering:
        case HazardClass::AtomicContention:
            return {
                {"MEM_INST_RETIRED.LOCK_LOADS", 1000, 10},
                {"MACHINE_CLEARS.MEMORY_ORDERING", 100, 1},
            };
        case HazardClass::LockContention:
            return {
                {"MEM_INST_RETIRED.LOCK_LOADS", 5000, 50},
                {"RESOURCE_STALLS.SB", 10000, 100},
            };
        case HazardClass::HeapAllocation:
            return {
                {"DTLB_LOAD_MISSES.WALK_COMPLETED", 1000, 10},
                {"PAGE_WALKER_LOADS.DTLB_L1", 5000, 50},
            };
        case HazardClass::StackPressure:
            return {
                {"DTLB_LOAD_MISSES.WALK_COMPLETED", 500, 5},
            };
        case HazardClass::VirtualDispatch:
        case HazardClass::StdFunction:
            return {
                {"BR_MISP_RETIRED.NEAR_CALL", 500, 5},
                {"FRONTEND_RETIRED.ITLB_MISS", 200, 2},
            };
        case HazardClass::DeepConditional:
            return {
                {"BR_MISP_RETIRED.ALL_BRANCHES", 5000, 50},
            };
        case HazardClass::NUMALocality:
            return {
                {"OFFCORE_RESPONSE.DEMAND_DATA_RD.ANY_RESPONSE", 50000, 500},
                {"UNC_CHA_TOR_INSERTS.IA_MISS", 10000, 100},
            };
        default:
            return {};
    }
}

LabelValue PMUTraceFeedbackLoop::evaluateCounters(
    const std::vector<PMUSample> &samples,
    HazardClass hc) const {

    auto thresholds = defaultThresholds(hc);
    if (thresholds.empty())
        return LabelValue::Unlabeled;

    unsigned confirmed = 0;
    unsigned refuted = 0;
    unsigned matched = 0;

    for (const auto &thresh : thresholds) {
        for (const auto &sample : samples) {
            if (sample.counterName != thresh.counterName)
                continue;

            matched++;

            double rate = static_cast<double>(sample.value);
            if (sample.duration_ns > 0)
                rate = rate * 1e9 / static_cast<double>(sample.duration_ns);

            if (rate >= thresh.confirmThreshold)
                ++confirmed;
            else if (rate <= thresh.refuteThreshold)
                ++refuted;
        }
    }

    if (matched == 0)
        return LabelValue::Unlabeled;

    if (confirmed > refuted && confirmed > 0)
        return LabelValue::Positive;
    if (refuted > confirmed && refuted > 0)
        return LabelValue::Negative;

    return LabelValue::Unlabeled;
}

void PMUTraceFeedbackLoop::updatePrior(HazardClass hc, LabelValue verdict) {
    std::string key(hazardClassName(hc));
    auto &prior = priors_[key];
    prior.hazardClass = hc;
    prior.totalObservations++;

    if (verdict == LabelValue::Positive)
        prior.confirmedHazards++;
    else if (verdict == LabelValue::Negative)
        prior.refutedHazards++;

    if (prior.totalObservations > 0) {
        prior.truePositiveRate =
            static_cast<double>(prior.confirmedHazards) /
            prior.totalObservations;
        prior.falsePositiveRate =
            static_cast<double>(prior.refutedHazards) /
            prior.totalObservations;

        double alpha = 1.0; /* Laplace smoothing */
        prior.priorConfidence =
            (prior.confirmedHazards + alpha) /
            (prior.totalObservations + 2.0 * alpha);
    }
}

} // namespace lshaz
