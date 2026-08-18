# Rule catalog

| Rule | Severity | Intent |
| --- | --- | --- |
| AUTH001 | warning | Owner and authorizer are not separated. |
| AUTH002–004 | error/warning | Approval timestamp is valid and precedes execution. |
| WIN001–003 | error | Window timestamps are valid, ordered, and unexpired. |
| SCOPE001–003 | error | Every action has known and explicitly allowed targets. |
| DEP001–003 | error | Dependencies exist, are not self-referential, and are acyclic. |
| TEL001 | warning | An action states expected telemetry. |
| TEL002 | error | Action telemetry references exist. |
| TEL003–005 | error/warning | Verification timestamps are valid, recent, and not in the future. |
| SAFE001–002 | error | Every action has stop and cleanup instructions. |
| SAFE003–004 | error | Production destructive actions are explicitly authorized and reversible. |
| DATA001 | warning | Production content access receives explicit review. |
| DET001 | warning | Every planned technique has a detection validation. |
| DET002 | note | A detection maps to a technique unused by the plan. |
| DET003–004 | warning/error | Detection telemetry is named and exists. |
| ATT001 | warning | A technique exists in the supplied current ATT&CK bundle. |
| PROD001–002 | warning | Plan environment and asset production flags agree. |
| WVR001–003 | error/warning/note | Waiver dates and applicability remain reviewable. |

Errors block readiness. Warnings reduce the score and fail only under `check --strict`. Notes are informational. Current waivers remove the finding from readiness and scoring but never remove it from output.
