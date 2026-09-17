# mkso

Code-enforced boundaries for LLM-assisted development.

A convincing explanation is not evidence that a feature meets its requirements.
Nor does a passing test, by itself, establish that an implementation stayed
within the agreed scope. mkso is being built to connect requirements, permitted
code changes, and the evidence needed to accept those changes.

The central principle is simple: **the LLM proposes the implementation; it does
not decide whether that implementation is accepted.**

mkso's intended role is the orchestration layer controlling the development
workflow, not another tool whose checks the model can choose to skip. This
repository contains implemented components and an experimental structural
drafting path. The complete end-to-end enforcement system is not yet finished.

## How it works

The intended workflow makes the boundaries explicit before implementation:

1. Express the agreed work as requirements, code subjects, and checkable
   obligations.
2. Prepare a small task scaffold and index it with SCIP before permitting edits.
   Each subsequent task builds on its predecessor, rather than resetting scope.
3. Let the implementer submit a narrowly scoped change through a broker that
   checks the permitted edit boundary and indexed structure.
4. Evaluate the resulting behavior independently and bind the evidence to the
   exact code and inputs it describes.
5. Accept or activate changes only through the applicable checks and approvals.

These are distinct stages. A structurally admitted draft is not a behaviorally
verified feature, and neither is automatically an approved deployment.

### Why SCIP is central

SCIP gives mkso concrete source identities to work with: files, symbol
definitions, and references. Requirements can be tied to indexed code rather
than just a model's description of what it changed.

In the current broker, the scaffold is indexed first. A submitted function body
is reconstructed inside its allowed slot and indexed again. The broker checks
that definitions match the scaffold and that references stay within its indexed
vocabulary. Surrounding source bytes remain outside the implementation slot.

These checks constrain code structure. They do not prove behavioral correctness
or complete requirement coverage; those need separate evidence.

## What is implemented

There are two useful entry points in this snapshot:

- **The local CLI and Python package** manage a work-item graph, obligations,
  source bindings, SCIP admission, evidence records, and freshness-aware checks.
  They also include a finite-state proof/certificate checker and JSON export.
- **The bootstrap drafting components** prepare indexed scaffolds, broker
  function-body submissions, and coordinate a container-based implementer.
  Their current output is a structural draft, not final feature acceptance.

For example, [the broker](bootstrap/baseline/broker.py) rejects submissions that
change surrounding syntax or introduce undeclared indexed definitions or
references. [The local evaluator](mkso/evaluation.py) checks for unresolved source
bindings, changed source, and missing or stale evidence instead of treating an
old passing result as permanently valid.

The local CLI stores its state in SQLite. Its `VERIFIED` status applies to the
configured local checks; it is not a private acceptance result or authorization
to activate code. The CLI and bootstrap components are not yet one complete,
production-qualified workflow.

## Quick start

For the local CLI, use Python **3.12 or later** and **uv 0.12.5**, as specified in
[the package metadata](pyproject.toml). No model API key or Docker daemon is
needed for the example below.

```sh
git clone https://github.com/AvivAvital2/mkso.git
cd mkso
uv sync --locked
uv run mkso --help
```

### Try a local check

From the repository directory, initialize a disposable project and inspect its
status:

```sh
MKSO_CLI="$PWD/.venv/bin/mkso"
MKSO_DEMO_DIR="$(mktemp -d)"
"$MKSO_CLI" init "$MKSO_DEMO_DIR"
(cd "$MKSO_DEMO_DIR" && "$MKSO_CLI" check)
```

The check prints:

```text
[INCOMPLETE] project
  - no active work-item graph
```

Exit code **1** is expected here. Initializing a database does not establish
that any work has been specified or verified. This is a local status example,
not an end-to-end implementation or acceptance demonstration.

Export that project's current state and evaluation as JSON:

```sh
(cd "$MKSO_DEMO_DIR" && "$MKSO_CLI" export --output snapshot.json)
```

Both the database (`.mkso/project.db`) and `snapshot.json` live in the temporary
directory, leaving the checkout unchanged. No code generation, model request,
private evaluation, or activation occurs in this example.

### Explore the commands

```sh
uv run mkso plan apply --help
uv run mkso stubs render --help
uv run mkso index scip --help
uv run mkso evidence run --help
uv run mkso model --help
```

SCIP indexing additionally needs an explicitly configured indexer, Protobuf
decoder, source contract, and matching tool identities. Live bootstrap drafting
also needs operator-provided runtime and deployment inputs. Installing the
Python package alone does not supply those prerequisites.

## Finding your way around

| Location | Purpose |
| --- | --- |
| [`mkso/`](mkso/) | CLI, requirements/evidence graph, SCIP handling, structural checks, and storage components |
| [`bootstrap/baseline/`](bootstrap/baseline/) | Draft broker, implementer bridge, and container runtime components |
| [`bootstrap/structural/orchestrator.py`](bootstrap/structural/orchestrator.py) | Preparation and constrained-writer lifecycle for a structural task |
| [`toolchain/scip-python/`](toolchain/scip-python/) | SCIP producer patch tooling |
| [`tests/`](tests/) | Public package tests, not private acceptance suites |

## Current limits

This is an early-development source snapshot, not a turnkey enforcement service.
In particular, approval verification in
[`bootstrap/baseline/authority.py`](bootstrap/baseline/authority.py) is still
unimplemented. Complete independent behavioral acceptance, qualified isolation,
and approved activation are not established by this release. A hash identifies
bytes; it does not, on its own, prove correctness or authorize a change.

The public repository intentionally omits confidential design and roadmap
documents, project policy specifications, private acceptance material, historical
task/evidence archives, and deployment-specific configuration. It is a filtered
source release, not a complete development-environment mirror. Do not add
credentials or private evaluation artifacts to it.

The vendored SCIP schema retains its
[upstream provenance and license notice](mkso/_schema/README.md).
