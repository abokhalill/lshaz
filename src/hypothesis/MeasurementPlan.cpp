// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/MeasurementPlan.h"

#include <sstream>

namespace lshaz {

bool MeasurementPlanGenerator::needsC2C(HazardClass hc) {
    return hc == HazardClass::FalseSharing ||
           hc == HazardClass::AtomicContention ||
           hc == HazardClass::ContendedQueue ||
           hc == HazardClass::HazardAmplification;
}

bool MeasurementPlanGenerator::needsNUMA(HazardClass hc) {
    return hc == HazardClass::NUMALocality ||
           hc == HazardClass::HazardAmplification;
}

bool MeasurementPlanGenerator::needsLBR(HazardClass hc) {
    return hc == HazardClass::VirtualDispatch ||
           hc == HazardClass::StdFunction ||
           hc == HazardClass::CentralizedDispatch ||
           hc == HazardClass::DeepConditional;
}

std::vector<CounterGroup> MeasurementPlanGenerator::partitionCounters(
    const PMUCounterSet &counterSet, uint32_t maxPerGroup) {

    std::vector<CounterGroup> groups;
    CounterGroup current;
    current.groupId = 0;

    for (const auto &c : counterSet.required) {
        if (current.counters.size() >= maxPerGroup) {
            groups.push_back(std::move(current));
            current = {};
            current.groupId = static_cast<uint32_t>(groups.size());
        }
        current.counters.push_back(c);
    }

    for (const auto &c : counterSet.optional) {
        if (current.counters.size() >= maxPerGroup) {
            groups.push_back(std::move(current));
            current = {};
            current.groupId = static_cast<uint32_t>(groups.size());
        }
        current.counters.push_back(c);
    }

    if (!current.counters.empty())
        groups.push_back(std::move(current));

    return groups;
}

CollectionScript MeasurementPlanGenerator::generatePerfStat(
    const std::vector<CounterGroup> &groups,
    const std::string &coreList) {

    std::ostringstream os;
    os << "#!/bin/bash\n"
       << "set -euo pipefail\n\n"
       << "VARIANT=${1:?\"Usage: $0 <treatment|control>\"}\n"
       << "CORES=\"" << coreList << "\"\n"
       << "RUNS=${RUNS:-5}\n\n";

    for (const auto &g : groups) {
        os << "# Counter group " << g.groupId << "\n";
        os << "EVENTS=\"";
        for (size_t i = 0; i < g.counters.size(); ++i) {
            os << g.counters[i].name;
            if (i + 1 < g.counters.size()) os << ",";
        }
        os << "\"\n";
        os << "taskset -c $CORES perf stat -e $EVENTS -r $RUNS "
           << "--detailed --output results/perf_stat_${VARIANT}_group"
           << g.groupId << ".txt "
           << "./experiment --variant ${VARIANT}\n\n";
    }

    return {"run_perf_stat.sh", os.str()};
}

CollectionScript MeasurementPlanGenerator::generatePerfC2C() {
    std::ostringstream os;
    os << "#!/bin/bash\n"
       << "set -euo pipefail\n\n"
       << "VARIANT=${1:?\"Usage: $0 <treatment|control>\"}\n\n"
       << "perf c2c record -o results/perf_c2c_${VARIANT}.data "
       << "./experiment --variant ${VARIANT}\n"
       << "perf c2c report -i results/perf_c2c_${VARIANT}.data "
       << "--stdio > results/c2c_report_${VARIANT}.txt\n";

    return {"run_perf_c2c.sh", os.str()};
}

CollectionScript MeasurementPlanGenerator::generatePerfLBR(
    const std::string &coreList) {

    std::ostringstream os;
    os << "#!/bin/bash\n"
       << "set -euo pipefail\n\n"
       << "VARIANT=${1:?\"Usage: $0 <treatment|control>\"}\n"
       << "CORES=\"" << coreList << "\"\n\n"
       << "taskset -c $CORES perf record -e cycles:pp -b --call-graph lbr "
       << "-o results/perf_lbr_${VARIANT}.data "
       << "./experiment --variant ${VARIANT}\n";

    return {"run_perf_lbr.sh", os.str()};
}

CollectionScript MeasurementPlanGenerator::generatePerfPEBS(
    const std::string &coreList) {

    std::ostringstream os;
    os << "#!/bin/bash\n"
       << "set -euo pipefail\n\n"
       << "VARIANT=${1:?\"Usage: $0 <treatment|control>\"}\n"
       << "CORES=\"" << coreList << "\"\n\n"
       << "taskset -c $CORES perf record "
       << "-e mem_load_retired.l3_miss:pp "
       << "-o results/perf_pebs_${VARIANT}.data "
       << "./experiment --variant ${VARIANT}\n";

    return {"run_perf_pebs.sh", os.str()};
}

CollectionScript MeasurementPlanGenerator::generateSetupEnv() {
    std::ostringstream os;
    os << "#!/bin/bash\n"
       << "set -euo pipefail\n\n"
       << "echo \"[lshaz] Configuring measurement environment\"\n\n"
       << "# Disable turbo boost\n"
       << "echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo "
       << "2>/dev/null || \\\n"
       << "    wrmsr -a 0x1a0 0x4000850089 2>/dev/null || true\n\n"
       << "# Set governor to performance\n"
       << "cpupower frequency-set -g performance\n\n"
       << "# Disable C-states beyond C0\n"
       << "for cpu in /sys/devices/system/cpu/cpu*/cpuidle/state[1-9]; do\n"
       << "    echo 1 > \"$cpu/disable\" 2>/dev/null || true\n"
       << "done\n\n"
       << "# Disable THP\n"
       << "echo never > /sys/kernel/mm/transparent_hugepage/enabled\n\n"
       << "# Disable ASLR\n"
       << "echo 0 > /proc/sys/kernel/randomize_va_space\n\n"
       << "# Record system state\n"
       << "mkdir -p results\n"
       << "uname -r > results/env_state.txt\n"
       << "lscpu >> results/env_state.txt\n"
       << "cat /proc/cpuinfo | grep \"model name\" | head -1 "
       << ">> results/env_state.txt\n"
       << "numactl --hardware >> results/env_state.txt 2>/dev/null || true\n"
       << "echo \"[lshaz] Environment configured\"\n";

    return {"setup_env.sh", os.str()};
}

CollectionScript MeasurementPlanGenerator::generateTeardownEnv() {
    std::ostringstream os;
    os << "#!/bin/bash\n"
       << "set -euo pipefail\n\n"
       << "echo \"[lshaz] Restoring environment\"\n\n"
       << "# Re-enable turbo boost\n"
       << "echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo "
       << "2>/dev/null || true\n\n"
       << "# Restore governor\n"
       << "cpupower frequency-set -g powersave 2>/dev/null || true\n\n"
       << "# Re-enable C-states\n"
       << "for cpu in /sys/devices/system/cpu/cpu*/cpuidle/state[1-9]; do\n"
       << "    echo 0 > \"$cpu/disable\" 2>/dev/null || true\n"
       << "done\n\n"
       << "# Re-enable THP\n"
       << "echo madvise > /sys/kernel/mm/transparent_hugepage/enabled "
       << "2>/dev/null || true\n\n"
       << "# Re-enable ASLR\n"
       << "echo 2 > /proc/sys/kernel/randomize_va_space\n\n"
       << "echo \"[lshaz] Environment restored\"\n";

    return {"teardown_env.sh", os.str()};
}

MeasurementPlan MeasurementPlanGenerator::generate(
    const LatencyHypothesis &hypothesis,
    const std::string &skuFamily,
    uint32_t maxCountersPerGroup) {

    MeasurementPlan plan;
    plan.hypothesisId = hypothesis.hypothesisId;
    plan.skuFamily = skuFamily;
    plan.maxCountersPerGroup = maxCountersPerGroup;
    plan.requiresC2C = needsC2C(hypothesis.hazardClass);
    plan.requiresNUMA = needsNUMA(hypothesis.hazardClass);
    plan.requiresLBR = needsLBR(hypothesis.hazardClass);

    plan.counterGroups = partitionCounters(
        hypothesis.counterSet, maxCountersPerGroup);

    std::string coreList = "4,5";

    plan.scripts.push_back(generateSetupEnv());
    plan.scripts.push_back(generatePerfStat(plan.counterGroups, coreList));

    if (plan.requiresC2C)
        plan.scripts.push_back(generatePerfC2C());
    if (plan.requiresLBR)
        plan.scripts.push_back(generatePerfLBR(coreList));

    plan.scripts.push_back(generatePerfPEBS(coreList));
    plan.scripts.push_back(generateTeardownEnv());

    return plan;
}

} // namespace lshaz
