// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/CalibrationFeedback.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>

namespace lshaz {

double CalibrationFeedbackStore::featureDistance(
    const std::vector<double> &a, const std::vector<double> &b) {
    if (a.size() != b.size() || a.empty())
        return std::numeric_limits<double>::max();
    double sum = 0.0;
    for (size_t i = 0; i < a.size(); ++i) {
        double d = a[i] - b[i];
        sum += d * d;
    }
    return std::sqrt(sum);
}

CalibrationFeedbackStore::CalibrationFeedbackStore(const std::string &storePath)
    : storePath_(storePath) {}

bool CalibrationFeedbackStore::validateSchema(
    const ExperimentResult &result) const {

    if (result.findingId.empty() || result.hypothesisId.empty())
        return false;
    if (result.schemaVersion.empty())
        return false;
    if (result.warmupIterations == 0 || result.measurementIterations == 0)
        return false;
    if (result.envState.cpuModel.empty())
        return false;
    return true;
}

LabelValue CalibrationFeedbackStore::assignLabel(
    const ExperimentResult &result) {

    switch (result.verdict) {
        case ExperimentVerdict::Confirmed:
            return LabelValue::Positive;
        case ExperimentVerdict::Refuted:
            return LabelValue::Negative;
        case ExperimentVerdict::Inconclusive:
            return LabelValue::Unlabeled;
        case ExperimentVerdict::Confounded:
            return LabelValue::Excluded;
        case ExperimentVerdict::Pending:
            return LabelValue::Unlabeled;
    }
    return LabelValue::Unlabeled;
}

double CalibrationFeedbackStore::computeLabelQuality(
    const ExperimentResult &result) {

    double powerFactor = std::min(result.power, 1.0);

    /* Degrade for missing confound controls. */
    double envQuality = 1.0;
    if (!result.envState.turboDisabled)
        envQuality -= 0.15;
    if (result.envState.governor != "performance")
        envQuality -= 0.10;
    if (result.envState.coresUsed.empty())
        envQuality -= 0.20;

    envQuality = std::max(envQuality, 0.0);

    double confoundRisk = 0.05; /* TODO: check disasm diff size */

    return powerFactor * envQuality * (1.0 - confoundRisk);
}

std::optional<LabeledRecord> CalibrationFeedbackStore::ingest(
    const ExperimentResult &result,
    const std::vector<double> &featureVector,
    HazardClass hazardClass) {

    if (!validateSchema(result))
        return std::nullopt;

    LabelValue label = assignLabel(result);
    double quality = computeLabelQuality(result);

    if (quality < 0.60 && label != LabelValue::Excluded)
        label = LabelValue::Unlabeled; /* reject noisy labels */

    if (result.power < 0.80 && label == LabelValue::Negative)
        label = LabelValue::Unlabeled; /* underpowered refutation → inconclusive */

    auto now = std::chrono::system_clock::now();
    uint64_t timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(
            now.time_since_epoch()).count());

    LabeledRecord record;
    record.findingId = result.findingId;
    record.hypothesisId = result.hypothesisId;
    record.hazardClass = hazardClass;
    record.featureVector = featureVector;
    record.label = label;
    record.labelQuality = quality;
    record.effectSize = result.effectSizeD;
    record.pValue = result.pValue;
    record.skuFamily = result.envState.skuFamily;
    record.kernelVersion = result.envState.kernel;
    record.schemaVersion = result.schemaVersion;
    record.ingestionTimestamp = timestamp;

    records_.push_back(record);

    /* FP registry: match on hazard class + feature neighborhood. */
    if (label == LabelValue::Negative) {
        bool found = false;
        for (auto &entry : falsePositiveRegistry_) {
            if (entry.hazardClass != hazardClass)
                continue;
            if (featureDistance(entry.features, featureVector) <= kNeighborhoodRadius) {
                ++entry.refutationCount;
                found = true;
                break;
            }
        }
        if (!found) {
            falsePositiveRegistry_.push_back(
                {featureVector, hazardClass, "Experimentally refuted", 1});
        }
    }

    return record;
}

std::vector<LabeledRecord> CalibrationFeedbackStore::queryByHazardClass(
    HazardClass hc) const {

    std::vector<LabeledRecord> result;
    for (const auto &r : records_) {
        if (r.hazardClass == hc)
            result.push_back(r);
    }
    return result;
}

std::vector<LabeledRecord> CalibrationFeedbackStore::queryBySKU(
    const std::string &skuFamily) const {

    std::vector<LabeledRecord> result;
    for (const auto &r : records_) {
        if (r.skuFamily == skuFamily)
            result.push_back(r);
    }
    return result;
}

bool CalibrationFeedbackStore::isKnownFalsePositive(
    const std::vector<double> &features,
    HazardClass hc) const {

    for (const auto &entry : falsePositiveRegistry_) {
        if (entry.hazardClass != hc)
            continue;
        if (entry.refutationCount < 3)
            continue;
        if (featureDistance(entry.features, features) <= kNeighborhoodRadius)
            return true;
    }
    return false;
}

void CalibrationFeedbackStore::registerFalsePositive(
    const std::vector<double> &features,
    HazardClass hc,
    const std::string &reason) {

    for (auto &entry : falsePositiveRegistry_) {
        if (entry.hazardClass != hc)
            continue;
        if (featureDistance(entry.features, features) <= kNeighborhoodRadius) {
            entry.reason = reason;
            ++entry.refutationCount;
            return;
        }
    }
    falsePositiveRegistry_.push_back({features, hc, reason, 1});
}

} // namespace lshaz
