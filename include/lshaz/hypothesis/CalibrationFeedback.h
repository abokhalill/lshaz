// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/hypothesis/EvidenceTier.h"
#include "lshaz/hypothesis/HazardClass.h"
#include "lshaz/hypothesis/LatencyHypothesis.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace lshaz {

struct LatencyPercentiles {
    double p50   = 0.0;
    double p99   = 0.0;
    double p99_9 = 0.0;
    double p99_99 = 0.0;
};

struct CounterDelta {
    std::string counterName;
    uint64_t treatment = 0;
    uint64_t control   = 0;
};

struct EnvironmentState {
    std::string kernel;
    std::string cpuModel;
    std::string skuFamily;
    std::vector<int> coresUsed;
    std::string numaTopology;
    std::string governor;
    bool turboDisabled = false;
};

struct ExperimentResult {
    std::string findingId;
    std::string hypothesisId;
    std::string schemaVersion;

    ExperimentVerdict verdict = ExperimentVerdict::Pending;
    double pValue     = 1.0;
    double effectSizeD = 0.0;
    double power       = 0.0;

    LatencyPercentiles treatmentLatency;
    LatencyPercentiles controlLatency;
    std::vector<CounterDelta> counterDeltas;

    EnvironmentState envState;

    uint64_t warmupIterations     = 0;
    uint64_t measurementIterations = 0;
    uint64_t ingestionTimestamp    = 0;
};

enum class LabelValue : uint8_t {
    Positive,    // Hazard confirmed exercised
    Negative,    // Hazard refuted
    Unlabeled,   // Inconclusive
    Excluded,    // Confounded or low quality
};

struct LabeledRecord {
    std::string findingId;
    std::string hypothesisId;
    HazardClass hazardClass;
    std::vector<double> featureVector;
    LabelValue label        = LabelValue::Unlabeled;
    double labelQuality     = 0.0;
    double effectSize       = 0.0;
    double pValue           = 1.0;
    std::string skuFamily;
    std::string kernelVersion;
    std::string schemaVersion;
    uint64_t ingestionTimestamp = 0;
};

struct CalibrationReport {
    std::string modelVersion;
    uint32_t trainingRecords  = 0;
    uint32_t testRecords      = 0;
    double brierScore         = 1.0;
    double maxCalibrationError = 1.0;
    double precisionHighCritical = 0.0;
    double recallCritical     = 0.0;
    double aucRoc             = 0.0;
    bool adversarialCorpusPass = false;
    std::string driftFlags;
};

class CalibrationFeedbackStore {
public:
    explicit CalibrationFeedbackStore(const std::string &storePath);

    std::optional<LabeledRecord> ingest(const ExperimentResult &result,
                                        const std::vector<double> &featureVector,
                                        HazardClass hazardClass);

    std::vector<LabeledRecord> queryByHazardClass(HazardClass hc) const;
    std::vector<LabeledRecord> queryBySKU(const std::string &skuFamily) const;
    size_t recordCount() const { return records_.size(); }

    /* Requires ≥3 refutations within kNeighborhoodRadius. */
    bool isKnownFalsePositive(const std::vector<double> &features,
                              HazardClass hc) const;

    void registerFalsePositive(const std::vector<double> &features,
                               HazardClass hc,
                               const std::string &reason);

private:
    static LabelValue assignLabel(const ExperimentResult &result);
    static double computeLabelQuality(const ExperimentResult &result);
    bool validateSchema(const ExperimentResult &result) const;

    static double featureDistance(const std::vector<double> &a,
                                  const std::vector<double> &b);

    static constexpr double kNeighborhoodRadius = 0.25;

    std::string storePath_;
    std::vector<LabeledRecord> records_;

    struct FalsePositiveEntry {
        std::vector<double> features;
        HazardClass hazardClass;
        std::string reason;
        uint32_t refutationCount = 0;
    };
    std::vector<FalsePositiveEntry> falsePositiveRegistry_;
};

} // namespace lshaz
