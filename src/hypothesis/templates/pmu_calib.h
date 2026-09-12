// SPDX-License-Identifier: Apache-2.0
//
// Coherence-counter election for generated experiment bundles.
//
// Embedded verbatim into every bundle by PMUCalibration.cpp; also compiled
// directly by pipeline_test, so the emitted harness and the tested code
// are the same text. The embedding wraps this file in a raw string literal
// delimited by LSHAZ_TPL; CMake refuses to configure if that delimiter's
// closing form ever appears below.
//
// Latency is a downstream, confounded proxy for coherence: a vCPU preemption
// or a P-state change inflates elapsed time without touching the mechanism.
// A cache-to-cache fill count cannot be manufactured that way, which is why
// the counter endpoint survives hosts the timing endpoint cannot.
#pragma once

#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <sched.h>
#include <cpuid.h>

#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <thread>
#include <vector>

struct lshaz_pmu_candidate {
    uint64_t config;
    char     name[40];
};

struct lshaz_pmu_instrument {
    bool     valid = false;
    uint64_t config = 0;
    char     name[40] = {0};
    double   ratio_lb = 0.0;      // Poisson lower bound, never a clamped point estimate
    uint64_t contended = 0;
    uint64_t isolated = 0;
    uint64_t measured_line = 0;   // where the cliff actually landed
};

enum lshaz_pmu_status {
    LSHAZ_PMU_OK = 0,
    LSHAZ_PMU_NO_ACCESS,        // counters unreadable: paranoid/vPMU/container
    LSHAZ_PMU_NO_CANDIDATE,     // vendor has no known coherence-fill encodings
    LSHAZ_PMU_NO_DISCRIMINATOR  // candidates exist, none reproduces the mechanism
};

// pure math

// Lower bound of the count ratio. A zero control arm must widen the interval,
// never be clamped to 1: clamping turns "below the measurement floor" into an
// unbounded score computed from a data point that does not exist, which ranks
// rare noise-driven events above the real one.
inline double lshaz_pmu_ratio_lb(uint64_t t, uint64_t c) {
    double tl = (double)t - 2.0 * std::sqrt((double)t);
    if (tl < 0.0) tl = 0.0;
    return tl / ((double)c + 2.0 * std::sqrt((double)c) + 1.0);
}

// Index of the first stride at which the count collapses and stays collapsed,
// or 0 when no such transition exists. Isolated from the measurement so it can
// be exercised against recorded curves on hosts with no PMU.
inline size_t lshaz_pmu_cliff_index(const uint64_t *curve, size_t n) {
    uint64_t mx = 0;
    for (size_t k = 0; k < n; ++k) if (curve[k] > mx) mx = curve[k];
    if (mx < 1000) return 0;                        // no statistical power
    const uint64_t hi = mx / 4, lo = mx / 100;
    for (size_t k = 1; k < n; ++k) {
        if (curve[k] > lo || curve[k - 1] < hi) continue;
        bool tail_low = true;
        for (size_t j = k; j < n; ++j)
            if (curve[j] > lo) { tail_low = false; break; }
        if (tail_low) return k;
    }
    return 0;
}

// counters

struct lshaz_pmu_read { uint64_t value, enabled, running; };

inline int lshaz_pmu_open(uint64_t cfg) {
    perf_event_attr a{};
    a.type = PERF_TYPE_RAW;
    a.size = sizeof a;
    a.config = cfg;
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    a.inherit = 0;
    a.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    return (int)syscall(__NR_perf_event_open, &a, 0, -1, -1, 0);
}

// A multiplexed counter returns a scaled estimate, and the scaling is
// invisible in the value alone. Refuse it rather than report an estimate as
// a measurement.
inline bool lshaz_pmu_read_exact(int fd, uint64_t *out) {
    lshaz_pmu_read r{};
    if (read(fd, &r, sizeof r) != (ssize_t)sizeof r) return false;
    if (r.running != r.enabled) {
        std::fprintf(stderr, "[lshaz] FATAL: PMU multiplexed (running=%llu "
            "enabled=%llu); counts would be scaled estimates.\n",
            (unsigned long long)r.running, (unsigned long long)r.enabled);
        return false;
    }
    *out = r.value;
    return true;
}

// Bracket a measured region with the elected instrument. Opens exactly one
// event, matching what calibration validated: a wider counter set can
// multiplex where a single counter did not, so the instrument in use would
// not be the instrument that was tested.
struct lshaz_pmu_scope {
    int fd;
    explicit lshaz_pmu_scope(uint64_t cfg) : fd(lshaz_pmu_open(cfg)) {
        if (fd < 0) {
            std::fprintf(stderr, "[lshaz] FATAL: elected counter %#llx would "
                "not open at measurement time.\n", (unsigned long long)cfg);
            std::abort();
        }
        ioctl(fd, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    }
    bool stop(uint64_t *out) {
        ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
        return lshaz_pmu_read_exact(fd, out);
    }
    ~lshaz_pmu_scope() { if (fd >= 0) close(fd); }
};

// candidates

inline void lshaz_pmu_push(std::vector<lshaz_pmu_candidate> &v,
                           uint64_t ev, uint64_t umask) {
    lshaz_pmu_candidate c{};
    c.config = (umask << 8) | ev;
    std::snprintf(c.name, sizeof c.name, "ev%#04llx.umask%#04llx",
                  (unsigned long long)ev, (unsigned long long)umask);
    v.push_back(c);
}

// Enumerate (event x umask), not event names. On Zen the discrimination lives
// in a single umask bit; an all-sources OR folds local-L2 and DRAM fills into
// the same counter, degrading signal-to-background by ~10x and destroying the
// cliff. Selecting by event name inherits the diluted default umask.
inline std::vector<lshaz_pmu_candidate> lshaz_pmu_candidates() {
    std::vector<lshaz_pmu_candidate> v;
    unsigned eax, ebx, ecx, edx;
    char vendor[13] = {0};
    if (__get_cpuid(0, &eax, &ebx, &ecx, &edx)) {
        std::memcpy(vendor + 0, &ebx, 4);
        std::memcpy(vendor + 4, &edx, 4);
        std::memcpy(vendor + 8, &ecx, 4);
    }

    if (std::strcmp(vendor, "AuthenticAMD") == 0) {
        // PMCx043 DataCacheFillsBySource, PMCx044 AnyFillsFromSys.
        for (uint64_t ev : {0x43ull, 0x44ull})
            for (int b = 0; b < 8; ++b) lshaz_pmu_push(v, ev, 1ull << b);
    } else if (std::strcmp(vendor, "GenuineIntel") == 0) {
        // MEM_LOAD_L3_HIT_RETIRED.XSNP_*. The umask is renamed across
        // generations (HITM pre-Ice Lake, FWD after), so sweep the bits
        // rather than encode a generation table.
        for (uint64_t ev : {0xD2ull, 0xD3ull})
            for (int b = 0; b < 4; ++b) lshaz_pmu_push(v, ev, 1ull << b);
    }

    // Escape hatch for silicon this table predates. The shape test still
    // adjudicates, so an override cannot smuggle in a non-coherence counter.
    if (const char *extra = std::getenv("LSHAZ_PMU_CANDIDATES")) {
        const char *p = extra;
        while (*p) {
            char *end = nullptr;
            uint64_t cfg = std::strtoull(p, &end, 0);
            if (end == p) break;
            lshaz_pmu_candidate c{};
            c.config = cfg;
            std::snprintf(c.name, sizeof c.name, "env:%#llx",
                          (unsigned long long)cfg);
            v.push_back(c);
            p = (*end == ',') ? end + 1 : end;
        }
    }
    return v;
}

// one arm

// The measured thread writes offset 0 in every arm, so its instruction stream
// is bit-identical across strides and only the peer's target moves.
//
// One peer is sufficient: the measured thread's own fill count saturates at a
// single continuous writer, because additional peers change which core steals
// the line rather than how often this one loses it. Per-thread attribution is
// what makes it saturate; a whole-process counter scales with writers.
inline bool lshaz_pmu_arm(uint64_t cfg, long stride, int peer_cpu,
                          uint64_t ops, uint64_t *out) {
    alignas(4096) static char region[8192];
    std::memset(region, 0, sizeof region);

    std::atomic<bool> go{false}, stop{false};
    std::atomic<int>  ready{0};

    volatile uint32_t *peer_slot =
        reinterpret_cast<volatile uint32_t *>(region + stride);
    std::thread peer([&] {
        cpu_set_t s; CPU_ZERO(&s); CPU_SET(peer_cpu, &s);
        sched_setaffinity(0, sizeof s, &s);
        ready.fetch_add(1, std::memory_order_release);
        while (!go.load(std::memory_order_acquire)) ;
        while (!stop.load(std::memory_order_relaxed))
            *peer_slot = *peer_slot + 1;
    });
    while (ready.load(std::memory_order_acquire) < 1) ;

    int fd = lshaz_pmu_open(cfg);
    if (fd < 0) { stop.store(true); peer.join(); return false; }

    volatile uint32_t *me = reinterpret_cast<volatile uint32_t *>(region);
    static volatile int spin = 0;
    go.store(true, std::memory_order_release);
    for (int w = 0; w < 400000; ++w) spin = spin + 1;   // peer reaches steady state

    ioctl(fd, PERF_EVENT_IOC_RESET, 0);
    ioctl(fd, PERF_EVENT_IOC_ENABLE, 0);
    for (uint64_t k = 0; k < ops; ++k) *me = *me + 1;
    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);

    bool ok = lshaz_pmu_read_exact(fd, out);
    close(fd);
    stop.store(true, std::memory_order_relaxed);
    peer.join();
    return ok;
}

// election

inline lshaz_pmu_instrument
lshaz_pmu_calibrate(uint64_t line_bytes, int peer_cpu, lshaz_pmu_status *st) {
    lshaz_pmu_instrument best;
    *st = LSHAZ_PMU_NO_CANDIDATE;

    auto cands = lshaz_pmu_candidates();
    if (cands.empty()) return best;

    std::vector<long> strides;
    for (long s = 4; s <= (long)line_bytes * 4; s *= 2) strides.push_back(s);

    bool any_opened = false;
    *st = LSHAZ_PMU_NO_DISCRIMINATOR;

    for (const auto &c : cands) {
        // Stage 1: cheap necessary condition, two points.
        uint64_t t = 0, i = 0;
        if (!lshaz_pmu_arm(c.config, 8, peer_cpu, 200000, &t)) continue;
        if (!lshaz_pmu_arm(c.config, (long)line_bytes, peer_cpu, 200000, &i))
            continue;
        any_opened = true;
        if (lshaz_pmu_ratio_lb(t, i) < 8.0) continue;

        // Stage 2: the mechanism signature. A two-point ratio shows only
        // that a counter separates the arms, which prefetch, store-buffer
        // occupancy and page locality also do, so stage 1 passes counters
        // sensitive to those. Requiring the collapse at the line size is what
        // lets calibration reject a discriminating non-coherence event.
        //
        // Median of repeats: one sample per stride lets a single descheduled
        // window invent or erase the collapse, and this shape test is the
        // only thing between a wrong counter and the verdict.
        std::vector<uint64_t> curve(strides.size(), 0);
        bool ok = true;
        for (size_t k = 0; k < strides.size() && ok; ++k) {
            uint64_t v[3];
            for (int r = 0; r < 3; ++r)
                if (!lshaz_pmu_arm(c.config, strides[k], peer_cpu, 500000, &v[r]))
                    { ok = false; break; }
            if (!ok) break;
            for (int a = 0; a < 3; ++a)
                for (int b = a + 1; b < 3; ++b)
                    if (v[b] < v[a]) { uint64_t t = v[a]; v[a] = v[b]; v[b] = t; }
            curve[k] = v[1];
        }
        if (!ok) continue;

        size_t cliff = lshaz_pmu_cliff_index(curve.data(), curve.size());
        if (cliff == 0) continue;                   // no cliff: not coherence

        if ((uint64_t)strides[cliff] != line_bytes) {
            std::fprintf(stderr, "[lshaz] WARN: %s collapses at %ldB but the "
                "configured line is %lluB. Either this counter is not measuring "
                "coherence, or the target line size is wrong for this host.\n",
                c.name, strides[cliff], (unsigned long long)line_bytes);
            continue;
        }

        // A challenger must be materially better, not merely luckier: two
        // genuine local-cache-fill encodings rank within noise of each other,
        // and an unstable election would change the reported instrument
        // between runs on one host.
        const double lb = lshaz_pmu_ratio_lb(curve[cliff - 1], curve[cliff]);
        if (best.valid && lb <= best.ratio_lb * 1.10) continue;
        best.valid = true;
        best.config = c.config;
        std::memcpy(best.name, c.name, sizeof best.name);
        best.ratio_lb = lb;
        best.contended = curve[cliff - 1];
        best.isolated = curve[cliff];
        best.measured_line = (uint64_t)strides[cliff];
    }

    if (!any_opened) { *st = LSHAZ_PMU_NO_ACCESS; return best; }
    if (best.valid) *st = LSHAZ_PMU_OK;
    return best;
}

inline void lshaz_pmu_report(const lshaz_pmu_instrument &in,
                             lshaz_pmu_status st, uint64_t line_bytes) {
    switch (st) {
    case LSHAZ_PMU_OK:
        std::fprintf(stderr, "[lshaz] PMU instrument elected: %s "
            "(collapse at %lluB == configured line, contended=%llu "
            "isolated=%llu, ratio_lb=%.0fx)\n", in.name,
            (unsigned long long)in.measured_line,
            (unsigned long long)in.contended,
            (unsigned long long)in.isolated, in.ratio_lb);
        return;
    case LSHAZ_PMU_NO_ACCESS:
        std::fprintf(stderr, "[lshaz] FATAL: no PMU counter could be opened. "
            "Raise perf_event_paranoid, or enable the vPMU if virtualized. "
            "Coherence verdict withheld.\n");
        return;
    case LSHAZ_PMU_NO_CANDIDATE:
        std::fprintf(stderr, "[lshaz] FATAL: no known coherence-fill encoding "
            "for this CPU vendor. Supply candidates via LSHAZ_PMU_CANDIDATES "
            "(they are still shape-tested). Coherence verdict withheld.\n");
        return;
    case LSHAZ_PMU_NO_DISCRIMINATOR:
        std::fprintf(stderr, "[lshaz] FATAL: counters are readable but none "
            "reproduced false sharing at a %lluB line on this host. The "
            "instrument is unvalidated; coherence verdict withheld.\n",
            (unsigned long long)line_bytes);
        return;
    }
}
