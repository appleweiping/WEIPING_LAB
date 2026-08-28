# WEIPING_LAB Result Contract v1.0

Experiment results are untrusted handoff artifacts. Their presence does not prove that an
experiment ran, and a label written by a producer is not evidence. `vlab resume` validates and
reclassifies every result before the writing phase can start.

## Canonical aggregate format

Store one `results.json` under
`workspace/ideas/<idea_id>/experiments/results/`:

```json
{
  "schema_version": "1.0",
  "idea_id": "idea-1234",
  "provenance": {
    "code_revision": "abc1234",
    "dataset_version": "dataset-v1",
    "config_digest": "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "command": "python -m experiments.run --config configs/block_1.yaml",
    "seed_values": [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
  },
  "blocks": [
    {
      "block_id": 1,
      "results": {
        "metrics": {
          "accuracy": 0.91,
          "f1": 0.89
        },
        "baselines": {
          "baseline-1": {"accuracy": 0.84},
          "baseline-2": {"accuracy": 0.85},
          "baseline-3": {"accuracy": 0.83},
          "baseline-4": {"accuracy": 0.86},
          "baseline-5": {"accuracy": 0.82},
          "baseline-6": {"accuracy": 0.85},
          "baseline-7": {"accuracy": 0.81},
          "baseline-8": {"accuracy": 0.84}
        },
        "statistics": {
          "p_value": 0.01,
          "confidence_interval": [0.03, 0.08],
          "effect_size": 0.52
        },
        "seeds_used": 20,
        "fair_comparison": true
      }
    }
  ]
}
```

One file per block is also supported. Use `block_<id>.json` and include the same
`schema_version`, `idea_id`, `block_id`, `provenance`, and `results` fields. When a plan contains
multiple blocks, an unnumbered flat file is rejected because its target is ambiguous.

## Deterministic evidence levels

`paper_result` requires all of the following:

- schema version `1.0`;
- at least the configured number of distinct `seed_values` (20 by default), matching
  `seeds_used`;
- a finite p-value in `[0, 1]` or a finite ordered confidence interval;
- a finite effect size;
- observed numeric values for every planned primary metric;
- observed numeric results for every planned baseline and at least eight baselines by default;
- `fair_comparison` exactly equal to JSON `true`;
- an immutable Git-style `code_revision`, a non-placeholder `dataset_version`, and a full
  `sha256:<64 hex>` `config_digest` provenance value.

`official` has the full seed count and statistical support but misses at least one
paper-result check. `diagnostic` has at least three effective seeds. Everything else is `pilot`.
Legacy flat JSON is accepted for continuity but cannot become `paper_result` because it has no
versioned schema.

An optional `_evidence_label` can only lower the computed level. It cannot promote evidence.

## Pipeline gates

- Every planned block must resolve to exactly one valid result entry.
- Duplicate block results, mismatched `idea_id`, unknown schema versions, invalid UTF-8/JSON,
  `NaN`/`Infinity`, and files over 5 MiB are rejected.
- At least one block must be `paper_result` before paper writing starts.
- The loader records the source filename and SHA-256 digest in `plan.json` under
  `_weiping_validation`.
- Extracted empirical claims must cite concrete block IDs, and every cited block must be
  `paper_result`. The final LLM audit cannot override this deterministic gate.

The bridge creates a plan-specific `experiments/result.example.json`. Replace every placeholder
with observed values; do not move the untouched example into `results/`.
