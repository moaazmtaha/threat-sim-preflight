# Contributing

Changes to policy semantics should begin with an issue and include the operational reason for the rule. Pull requests need focused `unittest` coverage and must pass `python -m compileall -q src tests`.

Do not add payload delivery, credential use, technique execution, infrastructure access, telemetry, or implicit network requests. User-controlled content in reports must remain escaped for its output format.

Contributions are licensed under the MIT License.
