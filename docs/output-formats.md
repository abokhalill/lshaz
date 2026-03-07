# Output Formats

lshaz supports three output formats: CLI (default), JSON, and SARIF 2.1.0.

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
  "version": "0.9.0",
  "schemaVersion": "2",
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

## Parse Failure Reporting

When TUs fail to parse, lshaz reports a summary on stderr:

```
lshaz: 79/157 TU(s) parsed, 246 diagnostic(s), 78 failed
  failed: src/broken.cpp
  failed: src/missing_dep.cpp
  ... and 76 more
```

Up to 10 failed files are listed. The full list is available in the JSON and SARIF `metadata`/`invocations` blocks.
