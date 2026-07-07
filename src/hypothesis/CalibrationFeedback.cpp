// SPDX-License-Identifier: Apache-2.0
#include "lshaz/hypothesis/CalibrationFeedback.h"

#include <llvm/Support/FileSystem.h>
#include <llvm/Support/JSON.h>
#include <llvm/Support/MemoryBuffer.h>
#include <llvm/Support/raw_ostream.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <limits>

namespace lshaz {

namespace {

const char *labelName(LabelValue v) {
    switch (v) {
        case LabelValue::Positive:  return "positive";
        case LabelValue::Negative:  return "negative";
        case LabelValue::Excluded:  return "excluded";
        case LabelValue::Unlabeled: return "unlabeled";
    }
    return "unlabeled";
}

LabelValue labelFromName(llvm::StringRef s) {
    if (s == "positive") return LabelValue::Positive;
    if (s == "negative") return LabelValue::Negative;
    if (s == "excluded") return LabelValue::Excluded;
    return LabelValue::Unlabeled;
}

llvm::json::Array toJson(const std::vector<double> &v) {
    llvm::json::Array a;
    for (double d : v) a.push_back(d);
    return a;
}

std::vector<double> doublesFrom(const llvm::json::Array *a) {
    std::vector<double> v;
    if (!a) return v;
    v.reserve(a->size());
    for (const auto &e : *a)
        v.push_back(e.getAsNumber().value_or(0.0));
    return v;
}

} // anonymous namespace

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

bool CalibrationFeedbackStore::load(std::string &err) {
    err.clear();
    if (storePath_.empty()) {
        err = "no store path configured";
        return false;
    }
    if (!llvm::sys::fs::exists(storePath_))
        return true; // first run: empty store

    auto buf = llvm::MemoryBuffer::getFile(storePath_);
    if (!buf) {
        err = "cannot read '" + storePath_ + "': " +
              buf.getError().message();
        return false;
    }

    auto parsed = llvm::json::parse((*buf)->getBuffer());
    if (!parsed) {
        err = "corrupt store '" + storePath_ + "': " +
              llvm::toString(parsed.takeError());
        return false;
    }
    const auto *root = parsed->getAsObject();
    if (!root || root->getInteger("version").value_or(0) != 1) {
        err = "unsupported store schema in '" + storePath_ + "'";
        return false;
    }

    records_.clear();
    falsePositiveRegistry_.clear();

    if (const auto *recs = root->getArray("records")) {
        records_.reserve(recs->size());
        for (const auto &e : *recs) {
            const auto *o = e.getAsObject();
            if (!o) { err = "malformed record in '" + storePath_ + "'"; return false; }
            auto hc = hazardClassFromName(
                o->getString("hazard_class").value_or("").str());
            if (!hc) { err = "unknown hazard_class in '" + storePath_ + "'"; return false; }
            LabeledRecord r;
            r.findingId     = o->getString("finding_id").value_or("").str();
            r.hypothesisId  = o->getString("hypothesis_id").value_or("").str();
            r.hazardClass   = *hc;
            r.featureVector = doublesFrom(o->getArray("features"));
            r.label         = labelFromName(o->getString("label").value_or(""));
            r.labelQuality  = o->getNumber("label_quality").value_or(0.0);
            r.effectSize    = o->getNumber("effect_size").value_or(0.0);
            r.pValue        = o->getNumber("p_value").value_or(1.0);
            r.skuFamily     = o->getString("sku_family").value_or("").str();
            r.kernelVersion = o->getString("kernel").value_or("").str();
            r.schemaVersion = o->getString("schema").value_or("").str();
            r.ingestionTimestamp = static_cast<uint64_t>(
                o->getInteger("ts").value_or(0));
            records_.push_back(std::move(r));
        }
    }

    if (const auto *fps = root->getArray("false_positives")) {
        falsePositiveRegistry_.reserve(fps->size());
        for (const auto &e : *fps) {
            const auto *o = e.getAsObject();
            if (!o) { err = "malformed fp entry in '" + storePath_ + "'"; return false; }
            auto hc = hazardClassFromName(
                o->getString("hazard_class").value_or("").str());
            if (!hc) { err = "unknown hazard_class in '" + storePath_ + "'"; return false; }
            FalsePositiveEntry fp;
            fp.features        = doublesFrom(o->getArray("features"));
            fp.hazardClass     = *hc;
            fp.reason          = o->getString("reason").value_or("").str();
            fp.refutationCount = static_cast<uint32_t>(
                o->getInteger("refutations").value_or(0));
            falsePositiveRegistry_.push_back(std::move(fp));
        }
    }

    return true;
}

bool CalibrationFeedbackStore::save(std::string &err) const {
    err.clear();
    if (storePath_.empty()) {
        err = "no store path configured";
        return false;
    }

    llvm::json::Array recs;
    for (const auto &r : records_) {
        recs.push_back(llvm::json::Object{
            {"finding_id", r.findingId},
            {"hypothesis_id", r.hypothesisId},
            {"hazard_class", std::string(hazardClassName(r.hazardClass))},
            {"features", toJson(r.featureVector)},
            {"label", labelName(r.label)},
            {"label_quality", r.labelQuality},
            {"effect_size", r.effectSize},
            {"p_value", r.pValue},
            {"sku_family", r.skuFamily},
            {"kernel", r.kernelVersion},
            {"schema", r.schemaVersion},
            {"ts", static_cast<int64_t>(r.ingestionTimestamp)},
        });
    }
    llvm::json::Array fps;
    for (const auto &fp : falsePositiveRegistry_) {
        fps.push_back(llvm::json::Object{
            {"hazard_class", std::string(hazardClassName(fp.hazardClass))},
            {"features", toJson(fp.features)},
            {"reason", fp.reason},
            {"refutations", static_cast<int64_t>(fp.refutationCount)},
        });
    }
    llvm::json::Object root{
        {"version", 1},
        {"records", std::move(recs)},
        {"false_positives", std::move(fps)},
    };

    llvm::SmallString<256> tmp;
    int fd = -1;
    if (auto ec = llvm::sys::fs::createUniqueFile(
            storePath_ + ".tmp.%%%%%%", fd, tmp)) {
        err = "cannot create temp file for '" + storePath_ + "': " + ec.message();
        return false;
    }
    {
        llvm::raw_fd_ostream out(fd, /*shouldClose=*/true);
        out << llvm::json::Value(std::move(root)) << "\n";
        out.flush();
        if (out.has_error()) {
            err = "write failed for '" + std::string(tmp) + "'";
            llvm::sys::fs::remove(tmp);
            return false;
        }
    }
    if (auto ec = llvm::sys::fs::rename(tmp, storePath_)) {
        err = "rename to '" + storePath_ + "' failed: " + ec.message();
        llvm::sys::fs::remove(tmp);
        return false;
    }
    return true;
}

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
