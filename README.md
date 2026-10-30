# HackerRank Orchestrate — Ghost Data Still Exists

## Submission package

This project is designed for the October 2026 HackerRank Orchestrate challenge.

The runnable submission is `code.zip`. The generated prediction file is `output.csv`.
The AI-agent transcript is `log.txt`.

### Run

From the repository root:

```bash
python code/main.py
```

The program reads participant-facing files from `dataset/` and writes:

```text
output.csv
```

with exactly:

```text
case_id,deletion_status,steps_json
```

### Architecture

1. **Request authorization** — detects deletion intent and rejects explicit access/correction/export/marketing/non-deletion requests.
2. **Identity resolution** — resolves the supplied email against the current identity snapshot and historical identity changes.
3. **Temporal cutoff** — ignores evidence captured after `audit_at`.
4. **Evidence retrieval** — selects the newest participant-visible evidence available by the cutoff that contains current or historical identifiers.
5. **Evidence parsing** — handles JSON, SQL-compatible text, logs and text records.
6. **Policy reasoning** — maps resource states to the supplied deletion policy:
   - account/search/export → delete
   - support/tombstone → redact
   - analytics → anonymize
   - integration data flow → disable
   - backup restore path → block
   - security audit records → retain
7. **Remediation planning** — orders data-flow/restore controls before dependent record changes.
8. **Verification planning** — emits required final-state checks.
9. **Deterministic serialization** — produces sorted cases, consecutive step numbers and valid JSON.

The public `sample_output.csv` is used only for public sample calibration/format validation. No organizer-only files are read.

## Important submission note

Do **not** put the `dataset/` directory, virtual environments, API keys, credentials, or nested ZIP archives inside `code.zip`.

The supplied challenge contract asks for:

```text
code/evaluation/evaluation_report.md
code/evaluation/usage_report.md
```

and those files are included.

## Limitations

The hidden canonical answers are not participant-visible, so hidden-dataset accuracy cannot be honestly claimed before HackerRank grading. The package therefore reports only reproducible public-sample and structural validation metrics rather than inventing hidden scores.
