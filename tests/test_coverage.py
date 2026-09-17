from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Protocol

import pytest

from mkso.coverage import CoverageJoinError, join_coverage_results
from mkso.manifest import apply_manifest
from mkso.store import Store
from mkso.stubs import render_stubs


def _raw(character: str) -> str:
    return character * 64


def _hash(character: str) -> str:
    return f"sha256:{_raw(character)}"


class _Mutation(Protocol):
    def __call__(self, case: _Case) -> None: ...


class _Store:
    def __init__(self, snapshot: dict[str, object]) -> None:
        self.snapshot = snapshot
        self.freshness_reasons: list[str] = []
        self.change_admission_after_first_read = False
        self.metadata_reads = 0

    def metadata(self, key: str) -> str | None:
        assert key == "active_scip_admission_hash"
        self.metadata_reads += 1
        if self.change_admission_after_first_read and self.metadata_reads > 1:
            return _raw("c")
        admission = self.snapshot["admission"]
        assert isinstance(admission, dict)
        value = admission["admission_hash"]
        assert isinstance(value, str)
        return value

    def scip_freshness_reasons(self) -> list[str]:
        return list(self.freshness_reasons)

    def scip_snapshot(self, admission_hash: str) -> dict[str, object] | None:
        admission = self.snapshot["admission"]
        assert isinstance(admission, dict)
        if admission_hash != admission["admission_hash"]:
            return None
        return deepcopy(self.snapshot)


@dataclass
class _Case:
    store: _Store
    objectives: list[dict[str, Any]]
    suite: dict[str, Any]
    suite_assignment: dict[str, Any]
    run: dict[str, Any]


def _scip_snapshot() -> dict[str, object]:
    admission_hash = _raw("4")
    ingestion_hash = _raw("5")
    return {
        "admission": {
            "admission_hash": admission_hash,
            "ingestion_hash": ingestion_hash,
        },
        "index": {
            "ingestion_hash": ingestion_hash,
            "index_hash": _raw("3"),
        },
        "documents": [
            {"relative_path": "src/a.py", "source_hash": _raw("1")},
            {"relative_path": "src/b.py", "source_hash": _raw("2")},
        ],
        "subject_bindings": [
            {
                "admission_hash": admission_hash,
                "subject_id": "subject.a",
                "document_path": "src/a.py",
                "symbol": "demo/a().",
                "source_hash": _raw("1"),
            },
            {
                "admission_hash": admission_hash,
                "subject_id": "subject.b",
                "document_path": "src/b.py",
                "symbol": "demo/b().",
                "source_hash": _raw("2"),
            },
        ],
    }


def _coverage_result(subject_id: str, source_hash: str, result: str) -> dict[str, Any]:
    return {
        "requirement_id": "coverage.reach",
        "subject_id": subject_id,
        "source_hash": source_hash,
        "scip_index_hash": _hash("3"),
        "raw_artifact_hash": _hash("b"),
        "trusted_parser_hash": _hash("a"),
        "measured_fraction": 1,
        "result": result,
    }


def _case() -> _Case:
    objective = {
        "objective_id": "objective.demo",
        "objective_hash": _hash("7"),
        "contract_hash": _hash("6"),
        "node_id": "task.demo",
        "obligation_id": "obligation.demo",
        "validation_profiles": [
            {"kind": "runtime_challenge", "channels": ["PRIMARY", "A"]},
            {"kind": "finite_exhaustive", "channels": ["PRIMARY", "B"]},
        ],
        "target_subjects": [
            {
                "subject_id": "subject.a",
                "source_path": "src/a.py",
                "scip_selector": "demo/a().",
            },
            {
                "subject_id": "subject.b",
                "source_path": "src/b.py",
                "scip_selector": "demo/b().",
            },
        ],
        "tool_ids": ["tool.coverage"],
        "coverage_requirements": [
            {
                "id": "coverage.reach",
                "kind": "subject_execution",
                "target": "both contract subjects execute",
                "subject_ids": ["subject.a", "subject.b"],
                "applicable_profiles": ["runtime_challenge"],
            },
            {
                "id": "coverage.finite",
                "kind": "finite_domain",
                "target": "the finite input set",
                "subject_ids": ["subject.a"],
                "applicable_profiles": ["finite_exhaustive"],
            },
        ],
    }
    suite = {
        "suite_origin": "blind",
        "lane": "A",
        "contract_hash": _hash("6"),
        "node_id": "task.demo",
        "objective_ids": ["objective.demo"],
        "objective_hashes": [_hash("7")],
        "suite_hash": _hash("8"),
        "strategy_assignments": [
            {"obligation_id": "obligation.demo", "profile": "runtime_challenge"}
        ],
        "coverage_bindings": [
            {
                "requirement_id": "coverage.reach",
                "subject_ids": ["subject.a", "subject.b"],
                "tool_id": "tool.coverage",
                "artifact_format": "coverage-json",
                "admission_rule": "trusted parser must bind every subject",
                "trusted_parser_id": "parser.coverage",
                "trusted_parser_hash": _hash("a"),
            }
        ],
    }
    suite_assignment = {
        "assignment_kind": "blind_fresh",
        "contract_hash": _hash("6"),
        "node_id": "task.demo",
        "channel": "A",
        "suite_lane": "A",
        "suite_hash": _hash("8"),
        "objective_ids": ["objective.demo"],
        "objective_hashes": [_hash("7")],
        "suite_assignment_hash": _hash("d"),
    }
    run = {
        "channel": "A",
        "contract_hash": _hash("6"),
        "node_id": "task.demo",
        "suite_hash": _hash("8"),
        "suite_assignment_hash": _hash("d"),
        "objective_hashes": [_hash("7")],
        "obligation_ids": ["obligation.demo"],
        "scip_index_hash": _hash("3"),
        "coverage_results": [
            _coverage_result("subject.b", _hash("2"), "VIOLATED"),
            _coverage_result("subject.a", _hash("1"), "SATISFIED"),
        ],
        "run_hash": _hash("9"),
    }
    return _Case(_Store(_scip_snapshot()), [objective], suite, suite_assignment, run)


def test_join_binds_each_pair_to_current_scip_without_interpreting_status() -> None:
    case = _case()

    joined = join_coverage_results(
        case.store, case.objectives, case.suite, case.suite_assignment, case.run
    )

    assert [entry.subject_id for entry in joined.entries] == ["subject.a", "subject.b"]
    assert [entry.reported_result for entry in joined.entries] == ["SATISFIED", "VIOLATED"]
    assert {entry.source_hash for entry in joined.entries} == {_hash("1"), _hash("2")}
    assert {entry.objective_hash for entry in joined.entries} == {_hash("7")}
    assert joined.scip_admission_hash == _raw("4")
    assert joined.scip_index_hash == _hash("3")

    case.run["coverage_results"].reverse()
    reordered = join_coverage_results(
        case.store, case.objectives, case.suite, case.suite_assignment, case.run
    )
    assert reordered == joined


def _remove_result(case: _Case) -> None:
    case.run["coverage_results"].pop()


def _duplicate_result(case: _Case) -> None:
    case.run["coverage_results"].append(deepcopy(case.run["coverage_results"][0]))


def _substitute_subject(case: _Case) -> None:
    case.run["coverage_results"][0]["subject_id"] = "subject.other"


def _stale_source(case: _Case) -> None:
    case.run["coverage_results"][0]["source_hash"] = _hash("c")


def _stale_result_index(case: _Case) -> None:
    case.run["coverage_results"][0]["scip_index_hash"] = _hash("c")


def _different_parser(case: _Case) -> None:
    case.run["coverage_results"][0]["trusted_parser_hash"] = _hash("c")


def _change_suite_subjects(case: _Case) -> None:
    case.suite["coverage_bindings"][0]["subject_ids"].pop()


def _change_target_path(case: _Case) -> None:
    case.objectives[0]["target_subjects"][0]["source_path"] = "src/b.py"


def _change_target_symbol(case: _Case) -> None:
    case.objectives[0]["target_subjects"][0]["scip_selector"] = "demo/other()."


def _use_undeclared_tool(case: _Case) -> None:
    case.suite["coverage_bindings"][0]["tool_id"] = "tool.other"


def _change_run_index(case: _Case) -> None:
    case.run["scip_index_hash"] = _hash("c")


def _remove_assignment(case: _Case) -> None:
    case.suite["strategy_assignments"].clear()


def _add_assignment(case: _Case) -> None:
    case.suite["strategy_assignments"].append(
        {"obligation_id": "obligation.other", "profile": "runtime_challenge"}
    )


def _change_objective_contract(case: _Case) -> None:
    case.objectives[0]["contract_hash"] = _hash("c")


def _change_suite_objective_hash(case: _Case) -> None:
    case.suite["objective_hashes"][0] = _hash("c")


def _change_run_objective_hash(case: _Case) -> None:
    case.run["objective_hashes"][0] = _hash("c")


def _change_run_suite_hash(case: _Case) -> None:
    case.run["suite_hash"] = _hash("c")


def _change_assignment_suite_hash(case: _Case) -> None:
    case.suite_assignment["suite_hash"] = _hash("c")


def _change_assignment_objective_hash(case: _Case) -> None:
    case.suite_assignment["objective_hashes"][0] = _hash("c")


def _change_assignment_channel(case: _Case) -> None:
    case.suite_assignment["channel"] = "B"


def _change_run_assignment_hash(case: _Case) -> None:
    case.run["suite_assignment_hash"] = _hash("c")


def _remove_scip_binding(case: _Case) -> None:
    case.store.snapshot["subject_bindings"].pop()  # type: ignore[union-attr]


def _desynchronize_scip_document(case: _Case) -> None:
    case.store.snapshot["documents"][0]["source_hash"] = _raw("c")  # type: ignore[index]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (_remove_result, "pairs differ"),
        (_duplicate_result, "repeats coverage result"),
        (_substitute_subject, "pairs differ"),
        (_stale_source, "stale source hash"),
        (_stale_result_index, "stale SCIP index hash"),
        (_different_parser, "used a different parser"),
        (_change_suite_subjects, "changed its frozen subject set"),
        (_change_target_path, "different SCIP source path"),
        (_change_target_symbol, "different SCIP symbol"),
        (_use_undeclared_tool, "uses undeclared tool"),
        (_change_run_index, "run is bound to a different SCIP index"),
        (_remove_assignment, "no strategy assignment"),
        (_add_assignment, "assignments do not exactly match"),
        (_change_objective_contract, "different contract hash"),
        (_change_suite_objective_hash, "do not exactly match the supplied objectives"),
        (_change_run_objective_hash, "not the suite's exact objective hash list"),
        (_change_run_suite_hash, "run suite hash differs"),
        (_change_assignment_suite_hash, "does not bind the exact contract, node, and suite"),
        (_change_assignment_objective_hash, "changes the suite objective identity"),
        (_change_assignment_channel, "run channel differs from the suite assignment"),
        (_change_run_assignment_hash, "run suite-assignment hash differs"),
        (_remove_scip_binding, "has no current SCIP binding"),
        (_desynchronize_scip_document, "inconsistent source hash"),
    ],
    ids=lambda value: value.__name__ if callable(value) else None,
)
def test_join_rejects_fail_open_permutations(mutate: _Mutation, message: str) -> None:
    case = _case()
    mutate(case)

    with pytest.raises(CoverageJoinError, match=message):
        join_coverage_results(
            case.store, case.objectives, case.suite, case.suite_assignment, case.run
        )


def test_join_rejects_a_stale_active_admission() -> None:
    case = _case()
    case.store.freshness_reasons.append("SCIP generation input is stale: src/a.py")

    with pytest.raises(CoverageJoinError, match="active SCIP admission is stale"):
        join_coverage_results(
            case.store, case.objectives, case.suite, case.suite_assignment, case.run
        )


def test_join_rejects_an_admission_switch_during_the_join() -> None:
    case = _case()
    case.store.change_admission_after_first_read = True

    with pytest.raises(CoverageJoinError, match="changed during the coverage join"):
        join_coverage_results(
            case.store, case.objectives, case.suite, case.suite_assignment, case.run
        )


def test_primary_channel_selects_every_applicable_primary_profile() -> None:
    case = _case()
    case.suite["suite_origin"] = "primary"
    case.suite["lane"] = "PRIMARY"
    case.suite["strategy_assignments"] = []
    case.suite_assignment["assignment_kind"] = "primary"
    case.suite_assignment["channel"] = "PRIMARY"
    case.suite_assignment["suite_lane"] = "PRIMARY"
    case.suite["coverage_bindings"].append(
        {
            "requirement_id": "coverage.finite",
            "subject_ids": ["subject.a"],
            "tool_id": "tool.coverage",
            "artifact_format": "coverage-json",
            "admission_rule": "trusted finite-domain parser accepts completeness",
            "trusted_parser_id": "parser.coverage",
            "trusted_parser_hash": _hash("a"),
        }
    )
    case.run["channel"] = "PRIMARY"
    finite_result = _coverage_result("subject.a", _hash("1"), "INCONCLUSIVE")
    finite_result["requirement_id"] = "coverage.finite"
    case.run["coverage_results"].append(finite_result)

    joined = join_coverage_results(
        case.store, case.objectives, case.suite, case.suite_assignment, case.run
    )

    assert [(entry.requirement_id, entry.subject_id) for entry in joined.entries] == [
        ("coverage.finite", "subject.a"),
        ("coverage.reach", "subject.a"),
        ("coverage.reach", "subject.b"),
    ]


def test_regression_uses_the_sealed_suite_assignment() -> None:
    case = _case()
    case.suite_assignment["assignment_kind"] = "blind_regression"
    case.suite_assignment["channel"] = "REGRESSION"
    case.run["channel"] = "REGRESSION"

    joined = join_coverage_results(
        case.store, case.objectives, case.suite, case.suite_assignment, case.run
    )

    assert joined.channel == "REGRESSION"


def test_join_reads_a_real_admitted_scip_snapshot(
    tmp_path, manifest_factory, ingest_calculator_scip
) -> None:
    store = Store.initialize(tmp_path)
    apply_manifest(store, manifest_factory(tmp_path))
    render_stubs(store)
    ingest_calculator_scip(store)
    snapshot = store.scip_snapshot()
    assert snapshot is not None
    [scip_binding] = snapshot["subject_bindings"]
    index = snapshot["index"]

    case = _case()
    objective = case.objectives[0]
    objective["target_subjects"] = [
        {
            "subject_id": "subject.add",
            "source_path": "src/calculator.py",
            "scip_selector": "scip-python python calculator 0.0.0 calculator/add().",
        }
    ]
    for requirement in objective["coverage_requirements"]:
        requirement["subject_ids"] = ["subject.add"]
    case.suite["coverage_bindings"][0]["subject_ids"] = ["subject.add"]
    case.run["scip_index_hash"] = f"sha256:{index['index_hash']}"
    case.run["coverage_results"] = [
        _coverage_result(
            "subject.add",
            f"sha256:{scip_binding['source_hash']}",
            "INCONCLUSIVE",
        )
    ]
    case.run["coverage_results"][0]["scip_index_hash"] = f"sha256:{index['index_hash']}"

    joined = join_coverage_results(
        store, case.objectives, case.suite, case.suite_assignment, case.run
    )

    assert len(joined.entries) == 1
    assert joined.entries[0].scip_symbol.endswith("calculator/add().")
    assert joined.scip_admission_hash == store.metadata("active_scip_admission_hash")
