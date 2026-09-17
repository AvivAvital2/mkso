"""mkso's public API.

The package deliberately keeps planning separate from admission.  An LLM may
propose a manifest, but only the deterministic loaders, checkers, and
hierarchical evaluator can change a project's verification status.
"""

from mkso.domain import EvidenceKind, NodeKind, NodeStatus, ObligationRole
from mkso.store import Store

__all__ = [
    "EvidenceKind",
    "NodeKind",
    "NodeStatus",
    "ObligationRole",
    "Store",
]

__version__ = "0.1.0"
