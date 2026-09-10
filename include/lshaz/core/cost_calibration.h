// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/cost.h"

#include <map>
#include <optional>
#include <string>
#include <vector>

namespace lshaz {

// Feedback that corrects the model rather than the finding.
//
// The existing calibration store labels findings confirmed or refuted and
// suppresses the ones that measured nothing. That helps exactly the finding
// it was measured on. A cost model can do better: the residual between what
// was predicted and what was measured belongs to the mechanism, so applying
// it corrects every future finding that composes the same terms, including
// ones in code nobody has measured.
//
// Keyed by mechanism, machine and workload together because the residual is
// a property of all three. A coherence miss hidden behind a syscall on a
// pipelined server is not the same event as the same miss in a compute loop,
// and averaging them produces a number describing neither.
// Invariant on the pair, and the one thing that lets two instruments share a
// key: predicted must be the quantity that this instrument's measured value
// is directly comparable to, so that the ratio is always a correction to the
// whole product.
//
// A throughput A/B removes the access and reads the difference, which is the
// full product including how much of the transfer the machine hid, so its
// predicted is the full product. A profiler counts transfers and reports
// their latency and says nothing about exposure, so its predicted is the
// product with the exposure term divided back out. Both ratios then multiply
// the same thing, because exposure multiplies through either way. Recording
// a measured occupancy against a predicted exposed cost does not, and the
// median would sit between two numbers describing different events.
struct CostObservation {
    std::string mechanism;
    std::string machine;
    std::string workload;
    Milli predicted = 0;
    Milli measured = 0;
};

class CostCalibration {
public:
    // Absent file is a valid empty store. Unreadable or malformed is an
    // error the caller must not scan through: proceeding would apply no
    // correction while the operator believes one is in effect.
    bool load(const std::string &path, std::string &err);
    bool save(const std::string &path, std::string &err) const;

    void observe(const CostObservation &o);

    // Median of measured/predicted over matching observations, with the
    // sample count. Median rather than a mean because one confounded run
    // should not move the correction, and because an integer median is
    // exact and order-independent where a geometric mean would need roots
    // and floating point.
    //
    // Nothing matching returns nothing, rather than a factor of one. A
    // neutral term that looks established would claim the model had been
    // checked here when it has not.
    struct Factor {
        Milli value = kMilli;
        unsigned samples = 0;
    };
    std::optional<Factor> factorFor(const std::string &mechanism,
                                    const std::string &machine,
                                    const std::string &workload) const;

    size_t size() const { return obs_.size(); }
    const std::vector<CostObservation> &observations() const { return obs_; }

    // Below this a correction is applied but reported unestablished, so it
    // can retire a finding and cannot promote one. Same asymmetry the rest
    // of the cost model uses: a single observation is a hint, not a law.
    static constexpr unsigned kTrustedSamples = 3;

private:
    std::vector<CostObservation> obs_;
};

} // namespace lshaz
