# Plan format

Plans are UTF-8 TOML or JSON documents no larger than 5 MiB. TOML is convenient for review; JSON is useful when another system generates the plan. Both map to the same fields.

## Plan metadata

`schema_version` must be `1`. The plan requires non-empty `title`, `owner`, `environment`, `change_ticket`, `evidence_store`, `authorizer`, `approved_at`, `window_start`, `window_end`, `timezone`, `stop_contact`, and `cleanup_owner` fields. Environment is `lab`, `staging`, or `production`. Timestamps use ISO 8601 and must include an offset.

## Scope

Each `scope` item has a stable `id`, `kind`, `owner`, and boolean `allowed` and `production` values. Actions can target only listed, allowed assets. Keeping denied assets in the plan makes a boundary explicit and testable.

## Actions

Every action requires an `id`, `name`, `technique_id`, `objective`, `targets`, `depends_on`, `expected_telemetry`, `cleanup`, and `stop_conditions`. The booleans `destructive`, `destructive_authorized`, and `reversible` make safety assumptions reviewable. `data_access` is `none`, `metadata`, or `content`.

Technique IDs must use ATT&CK form such as `T1059` or `T1059.001`. Format validation is always local; existence validation runs only when `--attack-stix` supplies a bundle.

## Telemetry and detections

Telemetry records require `id`, `source`, `owner`, and an offset-aware `verified_at` timestamp. Detection records bind a `technique_id` to an owner, one or more telemetry IDs, and a concrete `validation` condition.

## Waivers

A waiver has `rule_id`, `rationale`, `approved_by`, and an ISO date `expires`. A current waiver marks matching findings as waived but keeps them in Markdown, JSON, and SARIF. Expired or malformed waivers create their own finding. A waiver for a rule that is not currently failing is reported as a note.

```toml
[[waivers]]
rule_id = "DET001"
rationale = "Detection validation is the stated outcome of this isolated lab exercise."
approved_by = "Detection engineering lead"
expires = "2026-09-01"
```

Waivers apply by rule ID, so a waiver for a repeated rule suppresses every current instance. Split plans when exceptions must apply to only one action.
