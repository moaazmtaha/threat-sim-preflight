# threat-sim-preflight

Threat simulations often fail before execution: a target is implied but not listed, telemetry was never checked, one action depends on a step that no longer exists, or the cleanup owner is assumed rather than named.

`threat-sim-preflight` is an offline command-line gate for those failures. It reads a TOML or JSON plan, checks authorization and window metadata, resolves scope and dependencies, verifies safety and cleanup fields, measures detection coverage, and can validate technique IDs against a local MITRE ATT&CK STIX bundle. It does not execute techniques, deliver payloads, connect to infrastructure, or grant authorization.

## Useful checks

- Authorization timestamps, execution windows, stop contact, change reference, and accountable owners.
- Every action target against an explicit allow/deny scope list.
- Missing dependencies, self-dependencies, and cycles; a deterministic proposed execution order.
- Stop conditions, cleanup steps, reversibility, destructive-action authorization, and content-access warnings.
- Expected telemetry and detection validation coverage for every planned ATT&CK technique.
- Telemetry freshness and timestamp sanity.
- Expiring, approved waivers that remain visible in reports rather than silently disabling rules.
- Material plan drift: added/removed assets, actions, techniques, environment, and window changes.
- Markdown, JSON, and SARIF 2.1.0 reports suitable for review artifacts and CI.

## Quick start

Python 3.11 or newer is required; runtime checks use only the standard library.

```console
python -m pip install -e .
threat-sim-preflight validate examples/production-plan.toml
threat-sim-preflight check examples/production-plan.toml --as-of 2026-08-18T12:00:00+00:00
threat-sim-preflight report examples/production-plan.toml --as-of 2026-08-18T12:00:00+00:00 --out-dir report
```

Exit code `0` means the plan has no active errors. `1` means policy findings block readiness (or warnings remain with `check --strict`). `2` means the input itself is invalid.

## Local ATT&CK validation

Download an official Enterprise ATT&CK STIX bundle separately, keep its source and license information with your copy, then pass it locally:

```console
threat-sim-preflight check plan.toml --attack-stix enterprise-attack.json
```

The loader indexes current `attack-pattern` objects with a `mitre-attack` external reference and ignores revoked or deprecated entries. It performs no network request and caps the bundle at 100 MiB. The source dataset is maintained by MITRE in [attack-stix-data](https://github.com/mitre-attack/attack-stix-data).

## Plan drift

```console
threat-sim-preflight diff approved.toml proposed.toml
threat-sim-preflight diff approved.toml proposed.toml --format json
```

The diff is intentionally narrow. It calls out review-significant changes without pretending to replace a source-control diff.

## Plan format and policy

Start with [examples/production-plan.toml](examples/production-plan.toml). The field reference and waiver behavior are in [docs/plan-format.md](docs/plan-format.md), a JSON Schema is available at [schema/plan.schema.json](schema/plan.schema.json), and every rule and its intent is listed in [docs/rules.md](docs/rules.md).

The readiness score is a triage aid: 20 points per active error and 5 per active warning, floored at zero. A score does not authorize activity. The named authorizer, system owners, and applicable rules of engagement remain authoritative.

## Development

```console
python -m unittest discover -s tests -v
python -m compileall -q src tests
```

Security reports should follow [SECURITY.md](SECURITY.md). Contributions must not add technique execution, payload delivery, credential use, or hidden network behavior.
