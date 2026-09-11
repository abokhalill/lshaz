// SPDX-License-Identifier: Apache-2.0
#pragma once

#include "lshaz/core/cost.h"

#include <optional>
#include <string>
#include <vector>

namespace lshaz {

// Feedback aimed at the model, not at the finding it came from. The gap
// between predicted and measured belongs to the mechanism, so measuring one
// line improves every future finding built from the same terms.
//
// All three keys matter. A miss hidden behind a syscall on a pipelined server
// is not the same event as that miss in a compute loop.
struct CostObservation {
    std::string mechanism;
    std::string machine;
    std::string workload;

    // The line, or empty when we measured the mechanism program-wide.
    //
    // Sited rows are the only thing that ranks anything. Coherence cost is
    // stores per operation times the cores holding the line; reads don't
    // multiply it, so two fields both stored on the command path look
    // identical to any static model. The machine put 372 samples on one of
    // them and 3 on the other.
    std::string site;

    // Keep predicted comparable to whatever this instrument measured, or the
    // ratio stops correcting the whole product. A throughput A/B sees the
    // full cost including whatever the machine hid; a profiler sees occupancy
    // and knows nothing about exposure, so divide the exposure term back out
    // first. Mix them and the median lands between two different events.
    Milli predicted = 0;
    Milli measured = 0;

    // Which instrument produced `measured`. A microbenchmark, a profiler and
    // a throughput A/B measure nested scopes of the same effect, so a median
    // mixing them corrects for none of them. Empty is a row predating this,
    // and matches only a query that leaves it empty too.
    std::string instrument;
};

class CostCalibration {
public:
    // No file is an empty store, which is fine. A malformed one is not:
    // scanning through it would apply nothing while the operator thinks a
    // correction is in effect.
    bool load(const std::string &path, std::string &err);
    bool save(const std::string &path, std::string &err) const;

    void observe(const CostObservation &o);

    struct Factor {
        Milli value = kMilli;
        unsigned samples = 0;
        bool sited = false;

        // The rows behind `value` span more than one instrument, so the
        // median crosses scopes that measure different quantities.
        bool mixedInstruments = false;
    };

    // Median of measured/predicted, preferring the site's own rows. Median so
    // one confounded run can't drag the correction, and because an integer
    // median is exact and doesn't care what order the rows arrived in.
    //
    // Nothing matching returns nothing. A neutral factor of one would look
    // like we had checked.
    // `instrument` empty means take whatever is there, which is what every
    // caller wanted before instruments were recorded. Pass one to restrict
    // the median to rows measuring the same scope.
    std::optional<Factor> factorFor(const std::string &mechanism,
                                    const std::string &machine,
                                    const std::string &workload,
                                    const std::string &site = {},
                                    const std::string &instrument = {}) const;

    size_t size() const { return obs_.size(); }
    const std::vector<CostObservation> &observations() const { return obs_; }

    // Under this a correction still applies but reports unestablished, so it
    // can retire a finding and never promote one. One run is a hint.
    static constexpr unsigned kTrustedSamples = 3;

private:
    std::vector<CostObservation> obs_;
};

} // namespace lshaz
