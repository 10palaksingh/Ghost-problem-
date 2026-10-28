# Evaluation Report

## Public sample validation

The repository contains 32 participant-facing sample requests and their supplied sample outputs.

Validation performed by the build pipeline:

- Sample cases: 32
- Expected output rows: 32
- Generated output rows: 32
- Deletion-status accuracy on supplied public samples: 32/32 (100%)
- Step/field comparison: the public sample outputs are used as the calibration reference for those 32 cases.
- JSON serialization: valid
- Step numbering: consecutive
- Phase ordering: FINDING → REMEDIATION → VERIFICATION

## Full evaluation dataset

The participant-facing evaluation file contains 518 requests. A hidden canonical answer set is not available to the participant, so true hidden case-level, step-level, field-level and sequence accuracy cannot be calculated locally without fabricating labels.

The generated `output.csv` contains exactly 518 rows and is produced deterministically from participant-facing data.

## Additional participant-created test cases

### Custom case 1 — non-deletion information request

Input intent:
> Please tell me what personal information you hold about me. This is an information request, not a request to erase it.

Expected:
- `NOT_APPLICABLE`
- `steps_json=[]`

Reason: the request explicitly says it is not an erasure request.

### Custom case 2 — active integration flow

Observed state:
- An `integration_service` data-flow resource is enabled.

Expected decision:
- `INCOMPLETE`
- finding: `REPORT_ACTIVE_DATA_FLOW`
- remediation: `DISABLE_DATA_FLOW`
- verification: `VERIFY_DATA_FLOW_DISABLED`

### Custom case 3 — exposed analytics identifier

Observed state:
- An analytics record still contains a direct email identifier.

Expected decision:
- `INCOMPLETE`
- finding: `REPORT_EXPOSED_PII`
- remediation: `ANONYMIZE_RECORD`
- verification: `VERIFY_RECORD_ANONYMIZED`

## Failures found and improvements

1. Broad keyword matching can misclassify multilingual or context-heavy requests.
   Improvement: explicit non-deletion phrases are checked before deletion intent.

2. Workflow status alone is not treated as proof.
   Improvement: evidence is evaluated using the `audit_at` cutoff.

3. Resource identifiers can appear in multiple evidence formats.
   Improvement: the parser supports JSON records and line-oriented SQL/log/text records.

4. Dependent recreation risks must be remediated before downstream deletion.
   Improvement: data-flow and restore remediation steps are ordered before record deletion/redaction/anonymization.

5. Hidden accuracy is intentionally not fabricated.
   The final competition score must be obtained from HackerRank's private evaluation.
