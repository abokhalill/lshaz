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

Reads a **scan result** JSON (the output of `lshaz scan --format json`) and emits formal hypotheses for each diagnostic.

```bash
# Write hypotheses to a file
lshaz hyp scan-results.json --output hypotheses.json

# Write to stdout (default if --output is omitted)
lshaz hyp scan-results.json

# Filter by rule and minimum confidence
lshaz hyp scan-results.json --rule FL002 --min-conf 0.7 -o out.json
```

| Flag | Description |
|---|---|
| `-o, --output <file>` | Write hypothesis JSON to file (default: stdout) |
| `--rule <id>` | Only hypothesize for a specific rule ID |
| `--min-conf <f>` | Minimum confidence threshold (default: 0.0) |

Output includes H0/H1, required PMU counters, minimum detectable effect, and confound controls for each finding.

> **Important:** The input must be scan JSON (containing a `"diagnostics"` array). Passing hypothesis JSON (the output of `lshaz hyp`) will produce an error. The hypothesis file is an output artifact, not an input to further pipeline stages.

### `lshaz exp` — Synthesize Experiments

Generates runnable experiment bundles (treatment/control harnesses, build scripts, perf stat collection).

**Input:** `lshaz exp` requires the **original scan result JSON** — the same file you pass to `lshaz hyp`. It does **not** accept hypothesis JSON. If you pass hypothesis output by mistake, it will fail with:

```
lshaz exp: file contains hypothesis output, not scan results.
Pass the original scan JSON (from 'lshaz scan'), not the output of 'lshaz hyp'.
```

```bash
# Generate experiments into ./experiments/
lshaz exp scan-results.json --output ./experiments

# Preview without writing files
lshaz exp scan-results.json --dry-run

# Filter by rule and confidence
lshaz exp scan-results.json --rule FL002 --min-conf 0.7 -o ./experiments
```

| Flag | Description |
|---|---|
| `-o, --output <dir>` | Output directory (default: `./experiments`) |
| `--rule <id>` | Only generate for a specific rule ID |
| `--min-conf <f>` | Minimum confidence threshold (default: 0.5) |
| `--sku <name>` | CPU SKU family (default: `generic`) |
| `--dry-run` | Show what would be generated without writing |

Each experiment directory contains a README, Makefile, harness sources, and hypothesis metadata.

### Perf Access Requirements

Generated `scripts/run_all.sh` includes a **preflight check** for `perf_event_paranoid`. If the system restricts perf access (paranoid > 1) and the script is not run as root, it will fail immediately with actionable instructions:

```
[lshaz] ERROR: perf_event_paranoid=4 (needs <=1 or root)
  Fix: sudo sysctl kernel.perf_event_paranoid=1
  Or run this script with sudo.
```

To configure perf access system-wide:

```bash
# Temporary (until reboot)
sudo sysctl kernel.perf_event_paranoid=1

# Permanent
echo 'kernel.perf_event_paranoid=1' | sudo tee /etc/sysctl.d/99-perf.conf
sudo sysctl --system
```

On systems without passwordless sudo, either run the experiment script as root or configure `perf_event_paranoid` beforehand. The `setup_env.sh` and `teardown_env.sh` scripts also require root (they pin CPUs and disable frequency scaling).

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
