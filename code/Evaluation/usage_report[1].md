# Usage Report

## Final full-dataset run

The final local run uses a deterministic Python evidence-audit engine and does not call an external generative model.

- Model provider: none
- Model name: none
- Model calls: 0
- Input tokens: 0
- Output tokens: 0
- Total tokens: 0
- Average tokens per request: 0
- Estimated total cost: $0
- Estimated cost per request: $0

## Run scope

- Requests processed: 518
- Output rows produced: 518
- Output columns: `case_id,deletion_status,steps_json`
- Output location: repository root `output.csv`
- JSON serialization: deterministic compact JSON
- Case ordering: ascending `case_id`

## Why no model usage is reported

The challenge permits non-LLM implementations. This submission uses deterministic evidence retrieval and policy reasoning, which avoids API-key requirements and makes the run reproducible.

No credentials, API keys, or private configuration are included.
