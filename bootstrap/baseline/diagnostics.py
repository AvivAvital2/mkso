"""Operator-only fixed failure labels; never expose exception values or tracebacks."""

from pathlib import Path
from typing import TYPE_CHECKING as TYPE_CHECKING

ROOT = Path(__file__).resolve().parents[2]


def failure_stage(error: BaseException) -> str:
    """Classify at most 64 code-metadata frames without reading locals or messages."""
    # mkso:implementation:begin
    try:
        operator = str(ROOT / "bootstrap/baseline/container_operator.py")
        bridge = str(ROOT / "bootstrap/baseline/direct_bridge.py")
        labels = {
            (operator, "main"): "OPERATOR",
            (operator, "deployment"): "DEPLOYMENT",
            (operator, "prepare"): "CONTAINER_PREPARE",
            (operator, "run"): "CONTAINER_LIFECYCLE",
            (operator, "exchange"): "SESSION_IO",
            (operator, "serve"): "SESSION_PROTOCOL",
            (operator, "observed_provider"): "PROVIDER",
            (operator, "cleanup"): "CLEANUP",
            (bridge, "_credential"): "CREDENTIAL",
            (bridge, "_provider"): "PROVIDER",
            (bridge, "_call"): "RESPONSE_VALIDATION",
            (bridge, "_broker"): "BROKER",
            (bridge, "_dispatch"): "BROKER",
            (bridge, "_identity"): "IDENTITY",
            (bridge, "_projection"): "PUBLIC_CAPSULE",
        }
        trace = error.__traceback__
        stage = "UNKNOWN"
        for _ in range(64):
            if trace is None:
                return stage
            code = trace.tb_frame.f_code
            stage = labels.get((code.co_filename, code.co_name), stage)
            trace = trace.tb_next
        return stage if trace is None else "UNKNOWN"
    except Exception:
        return "UNKNOWN"
    # mkso:implementation:end
