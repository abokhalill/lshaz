// SPDX-License-Identifier: Apache-2.0
#include "FeedbackCommand.h"

#include "lshaz/hypothesis/CalibrationFeedback.h"
#include "lshaz/hypothesis/HypothesisConstructor.h"
#include "lshaz/hypothesis/HazardClass.h"

#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <cmath>
#include <cstring>
#include <fstream>
#include <string>
#include <vector>

namespace lshaz {

namespace {

struct SamplePair {
    uint64_t tsc_start;
    uint64_t tsc_end;
};

struct LatencyStats {
    double median   = 0;
    double p99      = 0;
    double p99_9    = 0;
    double p99_99   = 0;
    double mean     = 0;
    double stddev   = 0;
    uint64_t count  = 0;
};

bool loadSamples(const std::string &path, std::vector<double> &deltas) {
    std::ifstream in(path, std::ios::binary);
    if (!in.is_open()) return false;

    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);

    size_t nSamples = static_cast<size_t>(size) / sizeof(SamplePair);
    if (nSamples == 0) return false;

    std::vector<SamplePair> samples(nSamples);
    in.read(reinterpret_cast<char *>(samples.data()),
            static_cast<std::streamsize>(nSamples * sizeof(SamplePair)));

    deltas.reserve(nSamples);
    for (const auto &s : samples) {
        if (s.tsc_end > s.tsc_start)
            deltas.push_back(static_cast<double>(s.tsc_end - s.tsc_start));
    }
    return !deltas.empty();
}

LatencyStats computeStats(std::vector<double> &deltas) {
    LatencyStats st;
    st.count = deltas.size();
    if (deltas.empty()) return st;

    std::sort(deltas.begin(), deltas.end());

    auto percentile = [&](double p) -> double {
        size_t idx = static_cast<size_t>(p * (deltas.size() - 1));
        return deltas[std::min(idx, deltas.size() - 1)];
    };

    st.median = percentile(0.50);
    st.p99    = percentile(0.99);
    st.p99_9  = percentile(0.999);
    st.p99_99 = percentile(0.9999);

    double sum = 0;
    for (auto d : deltas) sum += d;
    st.mean = sum / deltas.size();

    double var = 0;
    for (auto d : deltas) var += (d - st.mean) * (d - st.mean);
    st.stddev = std::sqrt(var / deltas.size());

    return st;
}

/*
 * Welch's t-test (unequal variances).
 * Returns {t_statistic, approx_p_value, cohen_d}.
 */
struct TestResult {
    double t = 0;
    double p = 1.0;
    double d = 0;
};

TestResult welchTest(const LatencyStats &treatment,
                     const LatencyStats &control) {
    TestResult r;
    if (treatment.count < 30 || control.count < 30) return r;

    double se = std::sqrt(
        (treatment.stddev * treatment.stddev) / treatment.count +
        (control.stddev * control.stddev) / control.count);
    if (se < 1e-15) return r;

    r.t = (treatment.mean - control.mean) / se;

    double pooledSD = std::sqrt(
        (treatment.stddev * treatment.stddev +
         control.stddev * control.stddev) / 2.0);
    r.d = (pooledSD > 1e-15)
              ? (treatment.mean - control.mean) / pooledSD
              : 0.0;

    /* Conservative p-value approximation using normal tail. */
    double absT = std::abs(r.t);
    if (absT > 5.0)      r.p = 0.0001;
    else if (absT > 3.3)  r.p = 0.001;
    else if (absT > 2.58) r.p = 0.01;
    else if (absT > 1.96) r.p = 0.05;
    else if (absT > 1.64) r.p = 0.10;
    else                   r.p = 0.50;

    return r;
}

double normCdf(double x) {
    return 0.5 * std::erfc(-x / std::sqrt(2.0));
}

// one-sided normal quantile by bisection; no magic-constant approximation.
double normQuantile(double p) {
    double lo = 0.0, hi = 10.0;
    for (int i = 0; i < 60; ++i) {
        double mid = 0.5 * (lo + hi);
        (normCdf(mid) < p ? lo : hi) = mid;
    }
    return 0.5 * (lo + hi);
}

// post-hoc power to detect a relative effect `mde` of the control mean
// at the achieved sample sizes (two-sample z approximation). the previous
// hardcoded 0.50-if-not-significant made every refutation unlabelable:
// the >=0.80 power gate was structurally unsatisfiable.
double achievedPower(const LatencyStats &t, const LatencyStats &c,
                     double mde, double alpha) {
    if (t.count == 0 || c.count == 0 || c.mean <= 0.0)
        return 0.0;
    double se = std::sqrt(t.stddev * t.stddev / (double)t.count +
                          c.stddev * c.stddev / (double)c.count);
    if (se < 1e-15)
        return 1.0;
    double z = (mde * c.mean) / se - normQuantile(1.0 - alpha);
    return std::clamp(normCdf(z), 0.0, 1.0);
}

std::optional<HazardClass> parseHazardClass(llvm::StringRef name) {
    if (name == "CacheGeometry")       return HazardClass::CacheGeometry;
    if (name == "FalseSharing")        return HazardClass::FalseSharing;
    if (name == "AtomicOrdering")      return HazardClass::AtomicOrdering;
    if (name == "AtomicContention")    return HazardClass::AtomicContention;
    if (name == "LockContention")      return HazardClass::LockContention;
    if (name == "HeapAllocation")      return HazardClass::HeapAllocation;
    if (name == "StackPressure")       return HazardClass::StackPressure;
    if (name == "VirtualDispatch")     return HazardClass::VirtualDispatch;
    if (name == "StdFunction")         return HazardClass::StdFunction;
    if (name == "GlobalState")         return HazardClass::GlobalState;
    if (name == "ContendedQueue")      return HazardClass::ContendedQueue;
    if (name == "DeepConditional")     return HazardClass::DeepConditional;
    if (name == "NUMALocality")        return HazardClass::NUMALocality;
    if (name == "CentralizedDispatch") return HazardClass::CentralizedDispatch;
    if (name == "HazardAmplification") return HazardClass::HazardAmplification;
    if (name == "SynthesizedInteraction") return HazardClass::SynthesizedInteraction;
    return std::nullopt;
}

} // anonymous namespace

int runFeedbackCommand(int argc, const char **argv) {
    if (argc < 1 || (argc == 1 && std::strcmp(argv[0], "--help") == 0)) {
        llvm::errs()
            << "Usage: lshaz feedback <experiment-dir> [options]\n\n"
            << "Ingest experiment results into the calibration feedback store.\n\n"
            << "Reads hypothesis.json + results/{treatment,control}_samples.bin\n"
            << "from the experiment directory, computes Welch's t-test verdict,\n"
            << "and updates the calibration store.\n\n"
            << "Options:\n"
            << "  --store <path>  Calibration store path (required)\n"
            << "  --alpha <f>     Significance level (default: 0.01)\n"
            << "  --json          Output verdict as JSON\n"
            << "  --help          Show this help\n";
        return 0;
    }

    const char *expDir = argv[0];
    std::string storePath;
    double alpha = 0.01;
    bool jsonOutput = false;

    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "--store") == 0 && i + 1 < argc)
            storePath = argv[++i];
        else if (std::strcmp(argv[i], "--alpha") == 0 && i + 1 < argc)
            alpha = std::strtod(argv[++i], nullptr);
        else if (std::strcmp(argv[i], "--json") == 0)
            jsonOutput = true;
    }

    if (storePath.empty()) {
        llvm::errs() << "lshaz feedback: --store <path> is required\n";
        return 1;
    }

    /* Load hypothesis.json. */
    std::string hypPath = std::string(expDir) + "/hypothesis.json";
    auto hypBuf = llvm::MemoryBuffer::getFile(hypPath);
    if (!hypBuf) {
        llvm::errs() << "lshaz feedback: cannot read " << hypPath << "\n";
        return 1;
    }

    auto parsed = llvm::json::parse((*hypBuf)->getBuffer());
    if (!parsed) {
        llvm::errs() << "lshaz feedback: invalid JSON in " << hypPath << "\n";
        return 1;
    }

    auto *obj = parsed->getAsObject();
    if (!obj) {
        llvm::errs() << "lshaz feedback: expected JSON object in " << hypPath << "\n";
        return 1;
    }

    auto findingId    = obj->getString("finding_id").value_or("");
    auto hypothesisId = obj->getString("hypothesis_id").value_or("");
    auto hazardStr    = obj->getString("hazard_class").value_or("");
    auto evidenceStr  = obj->getString("evidence_tier").value_or("");
    auto mde          = obj->getNumber("minimum_detectable_effect").value_or(0.05);

    if (findingId.empty() || hypothesisId.empty()) {
        llvm::errs() << "lshaz feedback: missing finding_id or hypothesis_id\n";
        return 1;
    }

    auto hcOpt = parseHazardClass(hazardStr);
    if (!hcOpt) {
        llvm::errs() << "lshaz feedback: unknown hazard_class '" << hazardStr << "'\n";
        return 1;
    }

    /* Scan-side feature vector. Ingesting in any other space is a dead
       write: isKnownFalsePositive defines mismatched dimensions as
       infinitely distant, so the label could never suppress anything. */
    std::vector<double> features;
    if (const auto *sf = obj->getArray("structural_features")) {
        features.reserve(sf->size());
        for (const auto &v : *sf)
            features.push_back(v.getAsNumber().value_or(0.0));
    }
    if (features.empty()) {
        llvm::errs() << "lshaz feedback: hypothesis.json lacks "
                        "structural_features — regenerate the bundle "
                        "(lshaz exp); refusing to ingest into a feature "
                        "space the scanner cannot match\n";
        return 1;
    }

    /* Load TSC samples. */
    std::string treatPath = std::string(expDir) + "/results/treatment_samples.bin";
    std::string ctrlPath  = std::string(expDir) + "/results/control_samples.bin";

    std::vector<double> treatDeltas, ctrlDeltas;
    if (!loadSamples(treatPath, treatDeltas)) {
        llvm::errs() << "lshaz feedback: cannot load " << treatPath << "\n";
        return 1;
    }
    if (!loadSamples(ctrlPath, ctrlDeltas)) {
        llvm::errs() << "lshaz feedback: cannot load " << ctrlPath << "\n";
        return 1;
    }

    auto treatStats = computeStats(treatDeltas);
    auto ctrlStats  = computeStats(ctrlDeltas);
    auto test       = welchTest(treatStats, ctrlStats);

    double power = achievedPower(treatStats, ctrlStats, mde, alpha);

    /* Determine verdict. Non-significance only refutes when the run had
       the power to detect the MDE; otherwise it proves nothing. */
    ExperimentVerdict verdict;
    if (test.p <= alpha && test.d >= mde)
        verdict = ExperimentVerdict::Confirmed;
    else if (test.p > 0.10 && power >= 0.80)
        verdict = ExperimentVerdict::Refuted;
    else
        verdict = ExperimentVerdict::Inconclusive;

    /* Build ExperimentResult. */
    ExperimentResult expResult;
    expResult.findingId       = std::string(findingId);
    expResult.hypothesisId    = std::string(hypothesisId);
    expResult.schemaVersion   = "1.0.0";
    expResult.verdict         = verdict;
    expResult.pValue          = test.p;
    expResult.effectSizeD     = test.d;
    expResult.power           = power;
    expResult.warmupIterations     = 10000;
    expResult.measurementIterations = treatStats.count;

    /* setup_env.sh snapshots the applied environment; without it the
       quality gate keeps its penalties; degraded label, stated openly. */
    expResult.envState.cpuModel = "unknown";
    expResult.envState.governor = "unknown";
    std::string envPath = std::string(expDir) + "/results/env.json";
    if (auto envBuf = llvm::MemoryBuffer::getFile(envPath)) {
        auto envParsed = llvm::json::parse((*envBuf)->getBuffer());
        if (envParsed) {
            if (const auto *eo = envParsed->getAsObject()) {
                expResult.envState.governor =
                    eo->getString("governor").value_or("unknown").str();
                expResult.envState.cpuModel =
                    eo->getString("cpu_model").value_or("unknown").str();
                expResult.envState.kernel =
                    eo->getString("kernel").value_or("").str();
                expResult.envState.turboDisabled =
                    eo->getBoolean("turbo_disabled").value_or(false);
                if (const auto *cores = eo->getArray("cores"))
                    for (const auto &cv : *cores)
                        expResult.envState.coresUsed.push_back(
                            static_cast<int>(cv.getAsInteger().value_or(-1)));
            }
        } else {
            llvm::errs() << "lshaz feedback: warning: unparseable "
                         << envPath << " ("
                         << llvm::toString(envParsed.takeError())
                         << ") — label quality degraded\n";
        }
    } else {
        llvm::errs() << "lshaz feedback: warning: no results/env.json — "
                        "environment unverified, label quality degraded\n";
    }

    expResult.treatmentLatency.p50   = treatStats.median;
    expResult.treatmentLatency.p99   = treatStats.p99;
    expResult.treatmentLatency.p99_9 = treatStats.p99_9;
    expResult.treatmentLatency.p99_99 = treatStats.p99_99;

    expResult.controlLatency.p50   = ctrlStats.median;
    expResult.controlLatency.p99   = ctrlStats.p99;
    expResult.controlLatency.p99_9 = ctrlStats.p99_9;
    expResult.controlLatency.p99_99 = ctrlStats.p99_99;

    /* Load -> ingest -> persist. A verdict that never reaches disk never
       calibrates anything. */
    CalibrationFeedbackStore store(storePath);
    std::string storeErr;
    if (!store.load(storeErr)) {
        llvm::errs() << "lshaz feedback: " << storeErr << "\n";
        return 1;
    }
    auto record = store.ingest(expResult, features, *hcOpt);

    if (!record) {
        llvm::errs() << "lshaz feedback: ingestion rejected (schema validation)\n";
        return 1;
    }
    if (!store.save(storeErr)) {
        llvm::errs() << "lshaz feedback: " << storeErr << "\n";
        return 1;
    }

    if (jsonOutput) {
        llvm::outs()
            << "{\n"
            << "  \"hypothesis_id\": \"" << hypothesisId << "\",\n"
            << "  \"finding_id\": \"" << findingId << "\",\n"
            << "  \"verdict\": \"" << verdictName(verdict) << "\",\n"
            << "  \"p_value\": " << test.p << ",\n"
            << "  \"effect_size_d\": " << test.d << ",\n"
            << "  \"t_statistic\": " << test.t << ",\n"
            << "  \"treatment_mean_tsc\": " << treatStats.mean << ",\n"
            << "  \"control_mean_tsc\": " << ctrlStats.mean << ",\n"
            << "  \"treatment_p99_tsc\": " << treatStats.p99 << ",\n"
            << "  \"control_p99_tsc\": " << ctrlStats.p99 << ",\n"
            << "  \"treatment_samples\": " << treatStats.count << ",\n"
            << "  \"control_samples\": " << ctrlStats.count << ",\n"
            << "  \"label\": \"" << (record->label == LabelValue::Positive ? "positive"
                                     : record->label == LabelValue::Negative ? "negative"
                                     : record->label == LabelValue::Excluded ? "excluded"
                                     : "unlabeled") << "\",\n"
            << "  \"label_quality\": " << record->labelQuality << "\n"
            << "}\n";
    } else {
        llvm::outs()
            << "lshaz feedback: " << hypothesisId << "\n"
            << "  verdict:    " << verdictName(verdict) << "\n"
            << "  p-value:    " << test.p << "\n"
            << "  effect (d): " << test.d << "\n"
            << "  t-stat:     " << test.t << "\n"
            << "  treatment:  mean=" << treatStats.mean
            << " p99=" << treatStats.p99 << " (" << treatStats.count << " samples)\n"
            << "  control:    mean=" << ctrlStats.mean
            << " p99=" << ctrlStats.p99 << " (" << ctrlStats.count << " samples)\n"
            << "  label:      " << (record->label == LabelValue::Positive ? "positive"
                                    : record->label == LabelValue::Negative ? "negative"
                                    : record->label == LabelValue::Excluded ? "excluded"
                                    : "unlabeled")
            << " (quality=" << record->labelQuality << ")\n";
    }

    return 0;
}

} // namespace lshaz
