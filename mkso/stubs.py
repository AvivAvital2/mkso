"""Compile-valid Python stub generation from accepted planned bindings."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

from mkso.domain import PlannedBinding
from mkso.signatures import normalize_python_function_signature
from mkso.store import Store


def _normalized_signature(binding: PlannedBinding) -> tuple[str, str]:
    try:
        normalized, function_name = normalize_python_function_signature(binding.signature)
    except ValueError as exc:
        raise ValueError(f"{binding.obligation_id}: {exc}") from exc
    expected_name = binding.qualified_name.rsplit(".", 1)[-1]
    if function_name != expected_name:
        raise ValueError(
            f"{binding.obligation_id}: signature declares {function_name!r}, "
            f"but qualified_name ends in {expected_name!r}"
        )
    return normalized + ":", function_name


def render_stubs(store: Store) -> list[Path]:
    grouped: dict[str, list[PlannedBinding]] = defaultdict(list)
    for binding in store.bindings():
        grouped[binding.file].append(binding)
    created: list[Path] = []
    for relative_file, bindings in sorted(grouped.items()):
        if not relative_file.endswith(".py"):
            continue
        destination = store.project_root / relative_file
        if destination.exists():
            raise FileExistsError(
                f"refusing to overwrite existing source file: {relative_file}; "
                "change the accepted plan or authorize a separate edit slot"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        sections = [
            '"""Generated implementation skeletons.\n\n'
            "The accepted plan is authoritative; these docstrings are context, not proof.\n"
            '"""',
            "",
        ]
        for binding in sorted(bindings, key=lambda value: value.qualified_name):
            signature, _ = _normalized_signature(binding)
            doc = (
                f"Obligation: {binding.obligation_id}\n\n"
                f"Why this symbol exists:\n{binding.rationale}"
            )
            sections.extend(
                [
                    signature,
                    f"    {json.dumps(doc)}",
                    f"    raise NotImplementedError({json.dumps(binding.obligation_id)})",
                    "",
                    "",
                ]
            )
        destination.write_text("\n".join(sections).rstrip() + "\n", encoding="utf-8")
        created.append(destination)
    return created
