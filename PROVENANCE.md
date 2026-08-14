# Provenance

Agent Continuity Guard is original MIT-licensed work implemented from the
public behavioral specification in `docs/specs/v0.1-design.md`.

Runtime uses only Python standard-library facilities. Development-only tools
(`build`, `Hypothesis`, `jsonschema`, `mypy`, `pytest`, and `Ruff`) are not
runtime dependencies and do not enter the installed dependency graph.

Plan 1 installed artifacts identify themselves as package
`agent-continuity-guard`, version `0.1.0.dev0`, with wheel metadata managed by
the installer. This is an artifact identity boundary, not a release attestation
or authenticity signature. Audit anchors are canonical unsigned data; they are
tamper-evident only while an external anchor remains independently protected.

Public fixtures must use invented repositories, identities, data, and
scenarios. Private source, prose, names, paths, hashes, datasets, and failure
narratives are prohibited.
