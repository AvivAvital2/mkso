"""Proof-producing finite-state checker for ``all paths eventually``.

For a finite transition system, ``AF target`` holds at a state exactly when the
state belongs to the least fixed point containing the targets and every state
whose non-empty successor set is already in that fixed point.  A rank assigned
during this construction is a compact certificate: every transition strictly
decreases rank until a target (rank zero) is reached.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from itertools import pairwise
from pathlib import Path
from typing import Any

from mkso.hashing import hash_object


@dataclass(frozen=True, slots=True)
class Property:
    id: str
    source_states: tuple[str, ...]
    target_states: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class TransitionModel:
    states: tuple[str, ...]
    transitions: dict[str, tuple[str, ...]]
    properties: dict[str, Property]

    @property
    def normalized(self) -> dict[str, Any]:
        return {
            "states": sorted(self.states),
            "transitions": {
                state: sorted(self.transitions[state]) for state in sorted(self.states)
            },
            "properties": [
                {
                    "id": prop.id,
                    "kind": "all_paths_eventually",
                    "source_states": sorted(prop.source_states),
                    "target_states": sorted(prop.target_states),
                }
                for prop in sorted(self.properties.values(), key=lambda value: value.id)
            ],
        }

    @property
    def digest(self) -> str:
        return hash_object(self.normalized)


def load_model(path: Path) -> TransitionModel:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid model JSON: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != 1:
        raise ValueError("model schema_version must be 1")
    raw_states = raw.get("states")
    raw_transitions = raw.get("transitions")
    raw_properties = raw.get("properties")
    if not isinstance(raw_states, list) or not raw_states:
        raise ValueError("states must be a non-empty list")
    if not all(isinstance(value, str) and value for value in raw_states):
        raise ValueError("every state must be a non-empty string")
    states = tuple(raw_states)
    if len(set(states)) != len(states):
        raise ValueError("states must be unique")
    state_set = set(states)
    if not isinstance(raw_transitions, dict):
        raise ValueError("transitions must map every state to a list of successors")
    if set(raw_transitions) != state_set:
        missing = state_set - set(raw_transitions)
        extra = set(raw_transitions) - state_set
        raise ValueError(f"transition keys differ from states; missing={missing}, extra={extra}")
    transitions: dict[str, tuple[str, ...]] = {}
    for state, successors in raw_transitions.items():
        if not isinstance(successors, list) or not all(
            isinstance(value, str) for value in successors
        ):
            raise ValueError(f"transitions[{state!r}] must be a list of state names")
        unknown = set(successors) - state_set
        if unknown:
            raise ValueError(f"transitions[{state!r}] contains unknown states: {unknown}")
        transitions[state] = tuple(sorted(set(successors)))
    if not isinstance(raw_properties, list) or not raw_properties:
        raise ValueError("properties must be a non-empty list")
    properties: dict[str, Property] = {}
    for index, value in enumerate(raw_properties):
        if not isinstance(value, dict):
            raise ValueError(f"properties[{index}] must be an object")
        prop_id = value.get("id")
        if not isinstance(prop_id, str) or not prop_id:
            raise ValueError(f"properties[{index}].id must be a non-empty string")
        if prop_id in properties:
            raise ValueError(f"duplicate property ID: {prop_id}")
        if value.get("kind") != "all_paths_eventually":
            raise ValueError(f"{prop_id}: only all_paths_eventually is supported")
        sources = value.get("source_states")
        targets = value.get("target_states")
        if not isinstance(sources, list) or not sources:
            raise ValueError(f"{prop_id}.source_states must be a non-empty list")
        if not isinstance(targets, list) or not targets:
            raise ValueError(f"{prop_id}.target_states must be a non-empty list")
        if not set(sources) <= state_set or not set(targets) <= state_set:
            raise ValueError(f"{prop_id} refers to unknown states")
        properties[prop_id] = Property(
            id=prop_id,
            source_states=tuple(sorted(set(sources))),
            target_states=tuple(sorted(set(targets))),
        )
    return TransitionModel(states, transitions, properties)


def _counterexample(
    model: TransitionModel,
    prop: Property,
    ranks: dict[str, int],
) -> list[str]:
    targets = set(prop.target_states)
    current = next(state for state in prop.source_states if state not in ranks)
    path: list[str] = []
    seen: set[str] = set()
    while True:
        if current in seen:
            path.append(current)
            return path
        if current in targets:
            raise AssertionError("internal error: counterexample reached target")
        seen.add(current)
        path.append(current)
        successors = model.transitions[current]
        if not successors:
            return path
        non_winning = [state for state in successors if state not in ranks]
        if not non_winning:
            raise AssertionError("internal error: losing state has no losing successor")
        current = non_winning[0]


def prove(model: TransitionModel, property_id: str) -> dict[str, Any]:
    try:
        prop = model.properties[property_id]
    except KeyError as exc:
        raise KeyError(f"unknown property: {property_id}") from exc
    targets = set(prop.target_states)
    ranks: dict[str, int] = {state: 0 for state in targets}
    changed = True
    while changed:
        changed = False
        for state in sorted(model.states):
            if state in ranks:
                continue
            successors = model.transitions[state]
            if successors and all(successor in ranks for successor in successors):
                ranks[state] = 1 + max(ranks[successor] for successor in successors)
                changed = True
    common: dict[str, Any] = {
        "schema_version": 1,
        "checker": "mkso.af-rank.v1",
        "model_sha256": model.digest,
        "property": {
            "id": prop.id,
            "kind": "all_paths_eventually",
            "source_states": list(prop.source_states),
            "target_states": list(prop.target_states),
        },
    }
    if all(state in ranks for state in prop.source_states):
        return {
            **common,
            "result": "proved",
            "ranks": {state: ranks[state] for state in sorted(ranks)},
        }
    return {
        **common,
        "result": "disproved",
        "counterexample": _counterexample(model, prop, ranks),
    }


def check_certificate(model: TransitionModel, certificate: dict[str, Any]) -> tuple[bool, str]:
    if certificate.get("schema_version") != 1:
        return False, "certificate schema_version must be 1"
    if certificate.get("checker") != "mkso.af-rank.v1":
        return False, "unsupported certificate checker"
    if certificate.get("model_sha256") != model.digest:
        return False, "certificate model hash does not match"
    raw_property = certificate.get("property")
    if not isinstance(raw_property, dict):
        return False, "certificate property is missing"
    prop_id = raw_property.get("id")
    prop = model.properties.get(prop_id)
    if prop is None:
        return False, "certificate refers to an unknown property"
    expected_property = {
        "id": prop.id,
        "kind": "all_paths_eventually",
        "source_states": list(prop.source_states),
        "target_states": list(prop.target_states),
    }
    if raw_property != expected_property:
        return False, "certificate property differs from the model"
    targets = set(prop.target_states)
    result = certificate.get("result")
    if result == "proved":
        raw_ranks = certificate.get("ranks")
        if not isinstance(raw_ranks, dict) or not raw_ranks:
            return False, "proved certificate has no ranks"
        if not all(
            state in model.transitions
            and isinstance(rank, int)
            and not isinstance(rank, bool)
            and rank >= 0
            for state, rank in raw_ranks.items()
        ):
            return False, "certificate ranks are malformed"
        ranks = {str(state): int(rank) for state, rank in raw_ranks.items()}
        if not all(state in ranks for state in prop.source_states):
            return False, "not every source state has a rank"
        for state, rank in ranks.items():
            if rank == 0:
                if state not in targets:
                    return False, f"non-target state {state} has rank zero"
                continue
            if state in targets:
                return False, f"target state {state} must have rank zero"
            successors = model.transitions[state]
            if not successors:
                return False, f"ranked non-target state {state} is a dead end"
            for successor in successors:
                if successor not in ranks:
                    return False, f"successor {successor} of {state} has no rank"
                if ranks[successor] >= rank:
                    return False, f"rank does not decrease on {state} -> {successor}"
        return True, "proved certificate is valid"
    if result == "disproved":
        path = certificate.get("counterexample")
        if (
            not isinstance(path, list)
            or not path
            or not all(isinstance(state, str) for state in path)
        ):
            return False, "counterexample must be a non-empty state list"
        if path[0] not in prop.source_states:
            return False, "counterexample does not start at a source state"
        if any(state in targets for state in path):
            return False, "counterexample visits a target state"
        for left, right in pairwise(path):
            if right not in model.transitions.get(left, ()):
                return False, f"counterexample contains non-transition {left} -> {right}"
        end = path[-1]
        is_dead_end = not model.transitions[end]
        closes_cycle = end in path[:-1]
        if not (is_dead_end or closes_cycle):
            return False, "counterexample ends at neither a dead end nor a closed cycle"
        return True, "disproved certificate is valid"
    return False, "certificate result must be proved or disproved"


def load_certificate(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"invalid certificate JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("certificate root must be an object")
    return value
