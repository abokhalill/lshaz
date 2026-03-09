# Hypothesis Engine

The hypothesis engine generates formal experiment designs for runtime validation of flagged hazards. Activated by `--calibration-store`.

## Overview

The engine transforms static analysis findings into falsifiable experiments with measurable outcomes. It bridges the gap between structural analysis (compile-time) and runtime validation (PMU counters, latency measurements).

## Components

### HypothesisConstructor

Maps each diagnostic to a `LatencyHypothesis` containing:

| Field | Description |
|---|---|
| H0 (null hypothesis) | The flagged pattern does not cause measurable latency impact |
| H1 (alternative hypothesis) | The flagged pattern causes latency degradation exceeding the minimum detectable effect |
| Primary metric | p99 / p99.9 / p99.99 latency |
| Required PMU counters | Hardware counters needed to measure the effect |
| Optional PMU counters | Additional counters for deeper analysis |
| Minimum detectable effect | Smallest effect size the experiment can reliably detect |
| Significance level | α = 0.01 |
| Target power | 1 − β = 0.90 |
| Confound controls | Variables that must be held constant |

### ExperimentSynthesizer

Generates runnable experiment bundles written to disk:

- Treatment/control C++ harnesses
- Build scripts and Makefile
- `perf stat` collection scripts
- Hypothesis metadata JSON
- README with execution instructions

### MeasurementPlanGenerator

Partitions counter sets into hardware-compatible groups (respecting per-group counter limits) and generates:

- `perf stat` scripts for counter collection
- `perf c2c` scripts for false sharing detection
- `perf record -b` (LBR) scripts for branch analysis

### CalibrationFeedbackStore

Ingests experiment results and maintains:

- Per-diagnostic labels: Positive, Negative, Unlabeled, Excluded
- Per-rule false-positive rate tracking
- Feature-neighborhood false-positive registry (Euclidean distance, radius 0.25)

Safety rail: Critical or High severity findings with Proven evidence tier are never suppressed by calibration.

### PMUTraceFeedbackLoop

Closed-loop learning from production PMU traces:

1. Ingests counter data collected at flagged sites
2. Evaluates against per-hazard-class thresholds
3. Updates Bayesian priors
4. Feeds labeled records back into the calibration store

Priors persist across runs via `--pmu-priors`.

## CLI Subcommands

### `lshaz hyp` — Generate Hypotheses

Reads a JSON scan result and emits formal hypotheses for each diagnostic:

```bash
# From a scan result file
lshaz hyp scan-results.json

# Pipe from scan
lshaz scan . --format json | lshaz hyp -
```

Output includes H0/H1, required PMU counters, minimum detectable effect, and confound controls for each finding.

### `lshaz exp` — Synthesize Experiments

Generates runnable experiment bundles (treatment/control harnesses, build scripts, perf stat collection):

```bash
# Generate experiments into ./experiments/
lshaz exp scan-results.json --output ./experiments

# From pipe
lshaz scan . --format json | lshaz exp - --output ./experiments
```

Each experiment directory contains a README, Makefile, harness sources, and hypothesis metadata.

### Calibration Feedback

```bash
# Run with calibration store
lshaz scan . --calibration-store ./calibration.db

# With PMU trace feedback
lshaz scan . --calibration-store ./calibration.db \
  --pmu-trace ./pmu-data.tsv \
  --pmu-priors ./priors.json
```

## Limitations

Three hazard classes lack hypothesis templates: `DeepConditional` (FL050), `GlobalState` (FL040), and `CentralizedDispatch` (FL061). The hypothesis subsystem returns empty results for these classes.
