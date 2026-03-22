// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/hypothesis/LatencyHypothesis.h"
#include "lshaz/hypothesis/MeasurementPlan.h"

#include <string>
#include <vector>

namespace lshaz {

struct ExperimentFile {
    std::string relativePath;  // e.g., "src/treatment.cpp"
    std::string content;
};

struct ExperimentBundle {
    std::string findingId;
    std::string hypothesisId;
    std::string outputDir;
    std::vector<ExperimentFile> files;
    MeasurementPlan measurementPlan;
};

class ExperimentSynthesizer {
public:
    static ExperimentBundle synthesize(
        const LatencyHypothesis &hypothesis,
        const MeasurementPlan &plan,
        const std::string &outputDir);

    static bool writeToDisk(const ExperimentBundle &bundle);

private:
    static ExperimentFile generateCommonHeader(const LatencyHypothesis &hyp);
    static ExperimentFile generateHarness(const LatencyHypothesis &hyp);
    static ExperimentFile generateTreatment(const LatencyHypothesis &hyp);
    static ExperimentFile generateControl(const LatencyHypothesis &hyp);
    static ExperimentFile generateBuildScript(const LatencyHypothesis &hyp);
    static ExperimentFile generateRunAll(const MeasurementPlan &plan);
    static ExperimentFile generateMakefile();
    static ExperimentFile generateReadme(const LatencyHypothesis &hyp);
    static ExperimentFile generateHypothesisJson(const LatencyHypothesis &hyp);
};

} // namespace lshaz
