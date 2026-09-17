# mkso

Experimental Python tooling for code structure, SCIP indexing, constrained
implementation, and evidence handling.

This repository contains a public implementation snapshot and public unit tests.
It is not a complete or qualified end-to-end enforcement deployment. Some
components are unfinished, and deployment-specific inputs are not supplied.

## Contents

- `mkso/`: Python package and command-line entry point.
- `bootstrap/baseline/` and `bootstrap/structural/`: experimental broker,
  isolated-writer, and orchestration components.
- `tests/`: public package tests, not private acceptance suites.
- `toolchain/` and `implementation/`: SCIP-related source transformation tools.

## Local setup

The project requires Python 3.12 or later. The package metadata pins the
supported uv version.

```sh
uv sync --locked --extra dev
uv run mkso --help
```

SCIP-related operations require their applicable external toolchain and explicit
runtime configuration. Runtime files in this repository do not establish
qualification, trust, acceptance, or activation authority.

## Publication boundary

Design and roadmap documents, planning and review records, operational evidence,
private acceptance material, machine-readable project policy specifications,
credentials, and earlier repository history are intentionally not distributed.

The vendored SCIP schema retains its provenance notice in
`mkso/_schema/README.md`.
