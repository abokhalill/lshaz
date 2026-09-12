# Hypothesis Engine

Static analysis identifies structural risk; it cannot measure runtime impact.
The hypothesis engine closes that gap: it converts findings into falsifiable
experiments, measures them on hardware, and feeds the verdicts back into scan
calibration.

```
scan → hyp → exp → build/run → feedback → scan (with suppression)
```

Every stage is a standalone CLI subcommand operating on files; flags are in
[configuration.md](configuration.md).

## Stage 1: `lshaz hyp`, hypothesis construction

Maps each diagnostic to a `LatencyHypothesis`:

| Field | Content |
|---|---|
| H0 / H1 | Null: the flagged pattern has no measurable latency impact. Alternative: degradation exceeds the minimum detectable effect. |
| Primary metric | Tail latency percentile under test (p99 / p99.9 / p99.99) |
| PMU counters | Required and optional hardware counters, partitioned into groups that fit the PMU multiplexing limit |
| MDE | Minimum detectable effect (default 5% relative) |
| α, power | Significance 0.01, target power 0.90 |
| Confound controls | Turbo, C-states, THP, ASLR, governor, interrupt isolation |
| Structural features | The diagnostic's evidence vector, embedded for later calibration matching |

Every hazard class the rules emit has a hypothesis template. Evidence tier is
inferred from the structural evidence: AST-provable layout facts → `Proven`,
concurrency signals → `Likely`, otherwise `Speculative`.

Input is scan JSON. Hypothesis JSON is an output artifact, passing it back
into `hyp` or `exp` is rejected with an actionable error.

## Stage 2: `lshaz exp`, experiment synthesis

Generates one self-contained directory per hypothesis:

| Artifact | Purpose |
|---|---|
| `src/common.h` | Anti-elision primitives (`lshaz_do_not_optimize`, `lshaz_clobber_memory`), `lfence`-bracketed `rdtsc` |
| `src/treatment.cpp` | Kernel reproducing the hazard, parameterized by the diagnostic's structural evidence (`sizeof`, `estimated_frame`, `depth`, …) |
| `src/control.cpp` | The same kernel with the hazard removed (aligned, sharded, direct-dispatch, …) |
| `src/harness.cpp` | Warmup → measurement loop, core pinning, binary sample output; dispatches variants via `--variant` |
| `analyze` (built by the Makefile) | Bootstraps the (1−α) percentile CI of the **relative p99.9 effect** between arms (percentile-method bootstrap; `--bootstrap` reps, α configurable) |
| `Makefile` | Treatment and control compiled as **separate TUs**, linked into one binary. The compiler cannot optimize across the comparison boundary |
| `scripts/setup_env.sh` | Disables turbo/THP/ASLR/C-states, sets performance governor, records the achieved environment to `results/env.json` |
| `scripts/run_all.sh` | Preflight (`perf_event_paranoid` check) → build → per-variant runs with guarded PMU passes; any failed pass tears the environment down and exits non-zero rather than reporting partial results |
| `scripts/run_perf_stat.sh` / `run_perf_c2c.sh` | Counter collection partitioned to PMU limits; `perf c2c` for sharing/contention classes |
| `hypothesis.json` | Machine-readable hypothesis, including the structural features required by `feedback` |
| `README.md` | Human-readable design with the statistical parameters |
| `src/pmu_calib.h`, `pmu_sweep` | FL003 only. Coherence-counter election and the stride sweep that carries the verdict (below) |

13 hazard classes have dedicated treatment/control kernel generators.
CentralizedDispatch, HazardAmplification, and SynthesizedInteraction emit
editable stubs. Compound hazards need context a generator cannot invent.

### The coherence endpoint (FL003)

Elapsed time is a downstream, confounded proxy for coherence traffic. A vCPU
preemption or a P-state change inflates it without touching the mechanism, so
on a shared or virtualized host the timing endpoint goes bimodal and a single
sample per point can draw a step function out of scheduling noise. A
cache-to-cache fill count cannot be manufactured that way.

StripedArray bundles therefore run two endpoints in a fixed order of
authority. `pmu_sweep` counts coherence fills observed by the measured thread
and produces the verdict; the p99.9 latency arm corroborates when its
stability gate passes and is skipped, with the reason printed, when it does
not. A skipped latency arm never downgrades the coherence verdict.

Because a counter is only evidence once it has been shown to measure the
mechanism, `pmu_sweep` calibrates before it measures:

1. **Candidates** are enumerated as `(event, umask)` pairs, not event names,
   because the discrimination lives in a single umask bit: an all-sources OR
   folds local-L2 and DRAM fills into the same counter and smears the collapse
   away. `LSHAZ_PMU_CANDIDATES` appends raw configs for silicon the built-in
   table predates; they are shape-tested like any other.
2. **Stage 1** is a two-point ratio against a known-shared line, a necessary
   condition, cheap, and not sufficient.
3. **Stage 2** requires the count to collapse at exactly the configured line
   size, sampled as the median of repeats. The two arms differ in prefetch
   behaviour, store-buffer occupancy and page locality as well as coherence,
   so counters sensitive to any of those pass stage 1. Requiring the collapse
   at the line is what lets calibration *reject* a discriminating
   non-coherence event; a test that can only confirm is not a test.
4. **Ranking** uses a Poisson lower bound on the count ratio. A zero control
   arm widens the interval rather than being clamped to 1, clamping turns
   "below the measurement floor" into an unbounded score computed from a data
   point that does not exist, which ranks rare noise-driven events above the
   real one.

A counter that discriminates but collapses at the wrong stride is reported
rather than silently dropped: either it is not measuring coherence, or the
configured line size is wrong for the host. This is the only check in the
tool that can catch a mis-set target line size, which otherwise corrupts
FL001/FL002/FL003 verdicts uniformly and invisibly.

Every failure path withholds the verdict and names its remediation, no PMU
access, no known encoding for the vendor, no candidate reproducing the
mechanism, or a multiplexed counter (refused, since a scaled estimate is
indistinguishable from a count in the value alone). None of them fall back to
the timing endpoint, which is the proxy the counter replaced.

### Perf access

`run_all.sh` fails fast when `perf_event_paranoid` is too restrictive:

```bash
sudo sysctl kernel.perf_event_paranoid=1                  # until reboot
echo 'kernel.perf_event_paranoid=1' | sudo tee /etc/sysctl.d/99-perf.conf
sudo sysctl --system                                      # permanent
```

`setup_env.sh`/`teardown_env.sh` require root (frequency scaling, core
isolation).

## Stage 3: `lshaz feedback`, verdict ingestion

Reads `hypothesis.json`, `results/{treatment,control}_samples.bin`, and
`results/env.json`; computes per-arm percentile statistics, Welch's t-test,
and the **achieved power** at the observed sample sizes (two-sample z
approximation. Target power is a design parameter, achieved power is what
gates the verdict).

| Verdict | Criterion |
|---|---|
| Confirmed | p ≤ α and effect ≥ MDE |
| Refuted | p > 0.10 **and** achieved power ≥ 0.80 |
| Inconclusive | otherwise |

### Feedback and quality gates

Each verdict is stored as a labeled record with a quality score:

- Power factor (capped at 1.0)
- Environment quality from `results/env.json`, penalties for missing
  confound controls: turbo enabled −0.15, non-performance governor −0.10, no
  core pinning −0.20
- Confound risk margin

Labels below 0.60 quality demote to unlabeled. Underpowered refutations never
enter the false-positive registry: an experiment too weak to detect the
effect is not evidence of absence. Bundles missing structural features
(output of pre-feature tool versions) are refused outright.

### Calibration store

A versioned JSON file, written atomically (temp file + rename, a crashed
write cannot corrupt the store). An absent file is a valid empty store; an
unparseable file is a **hard error** (scan exits 3), scanning with silently
disabled calibration would misreport findings the user believes are
calibrated.

On subsequent scans with `--calibration-store`, a diagnostic is suppressed
when its 10-dimension structural feature vector falls within Euclidean radius
0.25 of a pattern with **≥3 refuted** instances. Safety rail: Critical/High
findings at `Proven` tier are never suppressed. Suppression counts are
reported in the scan summary.

## PMU trace feedback

A parallel ingestion path from production `perf stat` data
(`--pmu-trace <file>`): counters collected at flagged sites are evaluated
against per-hazard-class thresholds, updating a Bayesian prior per class that
blends with base confidence (production weight saturates at 50 observations).
Priors persist across runs via `--pmu-priors <file>`.
