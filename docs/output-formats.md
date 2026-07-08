# Output Formats

lshaz emits four formats, selected by `--format`: `cli` (default), `json`,
`sarif`, and `tidy`.

## Diagnostic model

Every diagnostic carries three orthogonal quality signals. Consumers should
treat them as independent axes, not redundant encodings:

| Signal | Type | Values | Semantics |
|---|---|---|---|
| Severity | enum | `Critical`, `High`, `Medium`, `Informational` | Worst-case latency impact if the hazard is exercised |
| Confidence | float | `[0.0, 1.0]` | Tool's belief that the hazard exists at this site, after IR refinement and evidence grading |
| Evidence tier | enum | `Proven`, `Likely`, `Speculative` | Strength of the structural guarantee. `Proven` means the layout forces the claim (e.g., line-aligned record with a same-line atomic pair). |

A Critical/`Likely` finding and a Medium/`Proven` finding are both actionable
— for different reasons. Calibration suppression never removes Critical or
High findings at `Proven` tier.

Per-diagnostic fields:

| Field | Description |
|---|---|
| `ruleID` | Producing rule (`FL002`) or synthesized ID (`FL091`, `B001`) |
| `title` | Rule title |
| `severity`, `confidence`, `evidenceTier` | As above |
| `location` | `file`, `line`, `column` (physical file; token-paste scratch buffers are resolved) |
| `functionName` | Enclosing function; empty for struct/variable-level findings |
| `hardwareReasoning` | The mechanism claim, with its assumptions stated inline |
| `structuralEvidence` | String map of measured facts (`sizeof`, `atomic_pairs_same_line`, `type_name`, `global_write_count`, …). Keys vary by rule. |
| `mitigation` | Specific remediation guidance |
| `escalations` | Trace of every severity/confidence adjustment with its reason — aggravating evidence, demotions (deliberate layout, missing write evidence), IR confirmations, cross-TU merge notes. The audit trail for "why this severity". |

## CLI format

Human-readable terminal output (default):

```
[CRITICAL] FL002 — False Sharing Candidate
  File: src/engine.h:42
  Evidence: sizeof=16B; atomic_pairs_same_line=1; atomics=yes; thread_escape=true
  Hardware: MESI invalidation ping-pong across cores...
  Mitigation: Pad independently-written fields to separate 64B cache lines...
```

A parse summary precedes diagnostics; a suppression summary (calibration,
cross-TU) follows them when applicable.

## JSON format

`--format json`. Top-level shape:

```json
{
  "version": "0.4.0",
  "schemaVersion": "1.0.0",
  "metadata": {
    "timestamp": 1751980800,
    "configPath": "lshaz.config.yaml",
    "irOptLevel": "O0",
    "irEnabled": true,
    "sourceFiles": ["src/engine.cpp"],
    "compilers": ["/usr/bin/cc"],
    "totalTUs": 157,
    "failedTUCount": 0,
    "failedTUs": []
  },
  "diagnostics": [
    {
      "ruleID": "FL002",
      "title": "False Sharing Candidate",
      "severity": "Critical",
      "confidence": 0.88,
      "evidenceTier": "proven",
      "location": { "file": "src/engine.h", "line": 42, "column": 8 },
      "functionName": "",
      "hardwareReasoning": "...",
      "structuralEvidence": { "sizeof": "16B", "atomics": "yes", "type_name": "Counters" },
      "mitigation": "...",
      "escalations": ["atomic fields 'head' and 'tail' share line 0: ..."]
    }
  ]
}
```

`metadata.totalTUs`, `failedTUCount`, and `failedTUs` describe parse health;
`failedTUs` lists the failing file paths.

## SARIF 2.1.0 format

`--format sarif`. Conforms to the
[SARIF 2.1.0 schema](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json);
consumable by GitHub Code Scanning and SARIF viewers.

Includes `tool.driver` (name, version, rules array), `invocations` (with
`totalTUs`/`failedTUCount`), `artifacts`, and per-result physical + logical
locations. Confidence, evidence tier, mitigation, and escalations ride in
`properties`.

```yaml
- name: Run lshaz
  run: lshaz scan . -f sarif -o results.sarif --no-ir

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

## Clang-tidy format

`--format tidy`. One line per diagnostic, plus `note:` lines for escalations —
parseable by anything that parses clang-tidy:

```
src/engine.h:42:8: error: False Sharing Candidate (...) [lshaz-FL002]
src/engine.h:42:8: note: atomic fields 'head' and 'tail' share line 0: guaranteed cross-core invalidation on write [lshaz-FL002]
```

Severity mapping: `Critical`/`High` → `error`, `Medium` → `warning`,
`Informational` → `note`.

Per-rule CI gates compose with `--rule`:

```bash
lshaz scan . -f tidy -r FL001            # gate on layout only
lshaz scan . -f tidy -r FL001 -r FL002   # layout + false sharing
```

A wrapper script is provided at `tools/lshaz-tidy`; see
`tools/github-actions-example.yml` for a ready-made workflow.

## Determinism

Output is **byte-identical across runs and across any `--jobs` value** on the
same input. The final order is severity (Critical first), then file path, then
line, with a total-order content tiebreaker — no comparison ends "equal" for
distinct diagnostics, so same-line findings from different symbols (macro-
pasted twins) cannot reorder under scheduling.

The machinery behind the guarantee — fork-isolated shards, canonical pre-pass
sort, map/reduce cross-TU aggregation, per-TU analysis lifetimes — is
documented in [architecture.md](architecture.md#determinism).

The only run-varying field is `metadata.timestamp`. For byte comparison in CI:

```bash
diff <(jq 'del(.metadata.timestamp)' run1.json) \
     <(jq 'del(.metadata.timestamp)' run2.json)

# or use the built-in comparator (also normalizes remote-scan temp paths):
lshaz diff run1.json run2.json
```

## Parse failure reporting

Failed TUs are reported on stderr with up to 10 file names listed:

```
lshaz: 79/157 TU(s) parsed, 246 diagnostic(s), 78 failed
  failed: src/broken.cpp
  ...and 76 more
```

The complete list is in JSON `metadata.failedTUs` and SARIF `invocations`.
When ≥3 TUs fail on the same missing header, post-processing emits a single
`B001` diagnostic naming that header — systematic build breakage surfaces as
one actionable finding instead of a wall of failures.
