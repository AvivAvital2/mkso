"""B-SEED-01 public scaffold; not an admitted approval verifier.

The source design fixes this interface. Verification remains unavailable until
the deployment/trust prerequisites and the implementation checkpoint are met.
Constructing these data objects confers no authority to take an action.
"""

from dataclasses import dataclass as _dataclass
from pathlib import Path as _Path
from typing import Literal as _Literal

__all__ = (
    "ApprovalAction",
    "ApprovalExpectation",
    "ApprovalRejected",
    "ApprovalTrust",
    "ApprovalUnavailable",
    "VerifiedApproval",
    "verify_approval",
)

ApprovalAction = _Literal["start_feature", "evaluate", "promote", "activate"]


class ApprovalRejected(ValueError):
    """The input does not establish the exact requested approval."""


class ApprovalUnavailable(RuntimeError):
    """Approval verification cannot be safely completed."""


@_dataclass(frozen=True, slots=True)
class ApprovalExpectation:
    """Exact action binding supplied only by the operator-owned call path."""

    action: ApprovalAction
    approval_id: str
    deployment_hash: str
    contract_hash: str
    semantic_contract_hash: str
    predecessor_acceptance_hash: str | None
    candidate_hash: str | None
    evidence_package_hash: str | None
    target_acceptance_hash: str | None


@_dataclass(frozen=True, slots=True)
class ApprovalTrust:
    """Operator-installed policy inputs; not self-authenticating caller data."""

    policy_hash: str
    principal: str
    public_key: str
    key_valid_after: int
    key_valid_before: int
    ssh_keygen_path: _Path
    ssh_keygen_hash: str
    revocations: bytes
    revocations_hash: str


@_dataclass(frozen=True, slots=True)
class VerifiedApproval:
    """Verified binding, never an action-consumption capability by itself."""

    approval_hash: str
    signature_hash: str
    trust_policy_hash: str
    expectation: ApprovalExpectation
    valid_after: int
    valid_before: int
    verified_at: int


def verify_approval(
    payload: bytes,
    signature: bytes,
    expected: ApprovalExpectation,
    trust: ApprovalTrust,
    verified_at: int,
) -> VerifiedApproval:
    """Authenticate exact payload/action, policy, signer and validity bindings.

    Implement strict canonical parsing and SSHSIG profile checks, followed by
    bounded verification with the pinned executable and exact revocation input.
    Return only after every check and cleanup succeeds. Never consume approval,
    evaluate, promote or activate. See the approved source design for all limits.
    """
    # MKSO-SLOT-BEGIN: B-SEED-01.verify_approval
    raise ApprovalUnavailable("Approval verification is not implemented")
    # MKSO-SLOT-END: B-SEED-01.verify_approval
