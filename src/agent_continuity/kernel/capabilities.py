"""Structured adapter capability claims."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Literal

from .canonical import CanonicalJSONError
from .model import Digest, JsonObject
from .records import require_digest, require_public_component

CapabilityStatus = Literal["proven", "unsupported", "unknown"]
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]{0,127}$")


@dataclass(frozen=True, slots=True)
class CapabilityClaimV1:
    name: str
    status: CapabilityStatus
    adapter_id: str
    adapter_version: str
    evidence_digest: Digest | None

    def __post_init__(self) -> None:
        if type(self.name) is not str or _CAPABILITY_RE.fullmatch(self.name) is None:
            raise CanonicalJSONError("capability name is invalid")
        if type(self.status) is not str or self.status not in {
            "proven",
            "unsupported",
            "unknown",
        }:
            raise CanonicalJSONError("capability status is invalid")
        if type(self.adapter_id) is not str or type(self.adapter_version) is not str:
            raise CanonicalJSONError("adapter identity must use plain strings")
        require_public_component(self.adapter_id, field="adapter identifier")
        require_public_component(self.adapter_version, field="adapter version")
        if self.status == "proven" and self.evidence_digest is None:
            raise CanonicalJSONError("proven capability requires evidence")
        if self.evidence_digest is not None:
            if type(self.evidence_digest) is not str:
                raise CanonicalJSONError("capability evidence must be a plain digest")
            require_digest(self.evidence_digest)


def capability_payload(claim: CapabilityClaimV1) -> JsonObject:
    return {
        "adapter_id": claim.adapter_id,
        "adapter_version": claim.adapter_version,
        "evidence_digest": claim.evidence_digest,
        "name": claim.name,
        "status": claim.status,
    }
