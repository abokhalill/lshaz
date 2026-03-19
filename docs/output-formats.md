# Output Formats

lshaz supports four output formats: CLI (default), JSON, SARIF 2.1.0, and Clang-Tidy.

## Diagnostic Model

Every diagnostic carries three orthogonal quality signals:

| Signal | Type | Values | Semantics |
|---|---|---|---|
| Severity | Enum | `Critical`, `High`, `Medium`, `Informational` | Worst-case latency impact if the hazard is exercised |
| Confidence | Float | `[0.0, 1.0]` | Tool's belief that the hazard exists at this site |
| Evidence Tier | Enum | `Proven`, `Likely`, `Speculative` | Strength of structural or IR-level backing |

Each diagnostic also includes:

| Field | Description |
|---|---|
| `ruleID` | Rule that produced the finding (e.g., `FL002`) |
| `location` | File, line, column |
| `functionName` | Enclosing function (empty for struct-level findings) |
| `hardwareReasoning` | Explanation of the hardware mechanism |
| `structuralEvidence` | Measured metrics (sizes, field counts, offsets) |
| `mitigation` | Specific remediation guidance |
| `escalations` | Ordered trace of confidence/severity adjustments with reasons |

---

## CLI Format

Human-readable terminal output. Default when `--format` is not specified.

```
[CRITICAL] FL002 — False Sharing Candidate
  File: src/engine.h:42
  Evidence: sizeof=16B; mutable_fields=[head,tail]; atomics=yes; thread_escape=true
  Hardware: MESI invalidation ping-pong across cores...
  Mitigation: Separate fields onto different cache lines.
```

---

## JSON Format

Machine-readable. Use `--format json`.

```json
{
  "version": "0.4.0",
  "schemaVersion": "1.0.0",
  "metadata": {
    "timestamp": 1709827200,
    "configPath": "lshaz.config.yaml",
    "irOptLevel": "O0",
    "irEnabled": false,
    "sourceFiles": ["src/engine.cpp"],
    "compilers": [],
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
      "evidenceTier": "likely",
      "location": { "file": "src/engine.h", "line": 42, "column": 1 },
      "functionName": "",
      "hardwareReasoning": "...",
      "structuralEvidence": { "sizeof": "16B", "atomics": "yes" },
      "mitigation": "...",
      "escalations": []
    }
  ]
}
```

The `metadata` block includes parse summary fields:
- `totalTUs` — total translation units submitted for analysis
- `failedTUCount` — number that failed to parse
- `failedTUs` — list of failed file paths

---

## SARIF 2.1.0 Format

Conforms to the [SARIF 2.1.0 schema](https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json). Use `--format sarif`.

Compatible with GitHub Code Scanning, VS Code SARIF Viewer, and other SARIF-consuming tools.

Includes:
- `tool.driver` with `name`, `version`, `informationUri`, `rules` array
- `invocations` with execution metadata (`totalTUs`, `failedTUCount`)
- `artifacts` from analyzed source files
- `results` with `ruleId`, `ruleIndex`, `level`, `message`, physical + logical locations
- `properties` with confidence, evidence tier, mitigation, escalations

### GitHub Actions Integration

```yaml
- name: Run lshaz
  run: lshaz scan . --format sarif --output results.sarif --no-ir

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Clang-Tidy Format

Compatible with clang-tidy tooling and CI log parsers. Use `--format tidy`.

Each diagnostic is emitted as:

```
file:line:col: severity: message [lshaz-FLXXX]
```

Example output:

```
src/engine.h:42:8: error: False Sharing Candidate (Struct 'Counters' (16B, 1 line(s)): 3 mutable field pair(s) share cache line(s).) [lshaz-FL002]
src/engine.h:42:8: note: atomic fields 'head' and 'tail' share line 0: guaranteed cross-core invalidation on write [lshaz-FL002]
```

Severity mapping: `Critical` → `error`, `High` → `error`, `Medium` → `warning`, `Informational` → `note`.

### Per-Rule CI Gating

Use `--rule` (repeatable) to run only specific rules. This enables per-check CI gates:

```bash
# Gate on cache layout issues only
lshaz scan . --format tidy --rule FL001

# Gate on false sharing only
lshaz scan . --format tidy --rule FL002

# Gate on multiple rules
lshaz scan . --format tidy --rule FL001 --rule FL002
```

A convenience wrapper script is provided at `tools/lshaz-tidy`:

```bash
./tools/lshaz-tidy /path/to/project --rule FL001
```

See `tools/github-actions-example.yml` for a ready-to-use GitHub Actions workflow.

---

## Determinism

Diagnostic output is **fully deterministic** across identical runs on the same input. Diagnostics are sorted by `(severity desc, file, line, column, ruleID)` — this order is stable and reproducible.

> **Note:** FL040 (Centralized Global State) uses a two-pass MapReduce architecture to guarantee determinism. Per-TU shards emit raw write counts; the pipeline aggregates them globally before applying the write-once threshold. Dedup uses a stable key (`var` + `type`) with a deterministic tiebreaker for canonical location. All diagnostic locations are resolved via `getSpellingLoc()` to strip Clang `<scratch space>` artifacts from macro expansions. See [architecture.md](architecture.md#parallel-execution) for details.

The only field that varies between runs is `metadata.timestamp` (epoch seconds at scan start). For byte-identical JSON comparison in CI, normalize or strip this field:

```bash
# Compare two runs (jq)
diff <(jq 'del(.metadata.timestamp)' run1.json) \
     <(jq 'del(.metadata.timestamp)' run2.json)

# Or use the built-in diff command
lshaz diff run1.json run2.json
```

Remote repository scans also produce unique temp directory paths in `metadata.sourceFiles`. Use `lshaz diff` which normalizes these automatically.

---

## Parse Failure Reporting

When TUs fail to parse, lshaz reports a summary on stderr:

```
lshaz: 79/157 TU(s) parsed, 246 diagnostic(s), 78 failed
  failed: src/broken.cpp
  failed: src/missing_dep.cpp
  ... and 76 more
```

Up to 10 failed files are listed. The full list is available in the JSON and SARIF `metadata`/`invocations` blocks.
