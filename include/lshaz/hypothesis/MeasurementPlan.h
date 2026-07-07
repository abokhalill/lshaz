// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/hypothesis/LatencyHypothesis.h"
#include "lshaz/hypothesis/PMUCounter.h"

#include <cstdint>
#include <string>
#include <vector>

namespace lshaz {

struct CounterGroup {
    uint32_t groupId;
    std::vector<PMUCounter> counters;
};

struct CollectionScript {
    std::string name;       // e.g., "run_perf_stat.sh"
    std::string content;    // Shell script content
};

struct MeasurementPlan {
    std::string hypothesisId;
    std::string skuFamily;          // Detected or configured
    std::vector<CounterGroup> counterGroups;
    std::vector<CollectionScript> scripts;
    uint32_t maxCountersPerGroup;   // Hardware limit (typically 4-8)
    bool requiresC2C  = false;
    bool requiresNUMA = false;
    bool requiresLBR  = false;
};

class MeasurementPlanGenerator {
public:
    static MeasurementPlan generate(const LatencyHypothesis &hypothesis,
                                    const std::string &skuFamily = "generic",
                                    uint32_t maxCountersPerGroup = 4);

private:
    static std::vector<CounterGroup> partitionCounters(
        const PMUCounterSet &counterSet, uint32_t maxPerGroup);
    static CollectionScript generatePerfStat(
        const std::vector<CounterGroup> &groups,
        const std::string &coreList);
    static CollectionScript generatePerfC2C();
    static CollectionScript generatePerfLBR(const std::string &coreList);
    static CollectionScript generatePerfPEBS(const std::string &coreList);
    static CollectionScript generateSetupEnv(const std::string &coreList);
    static CollectionScript generateTeardownEnv();
    static bool needsC2C(HazardClass hc);
    static bool needsNUMA(HazardClass hc);
    static bool needsLBR(HazardClass hc);
};

} // namespace lshaz
