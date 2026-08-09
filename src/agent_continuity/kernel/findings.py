"""Normalized non-PASS findings."""

from __future__ import annotations

import re
from dataclasses import dataclass

from .canonical import CanonicalJSONError, canonical_bytes
from .evaluation import Verdict
from .model import JsonObject, RecordId
from .records import require_digest

_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_MESSAGE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,191}$")


@dataclass(frozen=True, slots=True)
class Finding:
    code: str
    verdict: Verdict
    subject_id: RecordId
    message_id: str
    parameters: JsonObject
    integrity_failure: bool = False

    def __post_init__(self) -> None:
        if _CODE_RE.fullmatch(self.code) is None:
            raise CanonicalJSONError("finding code is invalid")
        if _MESSAGE_RE.fullmatch(self.message_id) is None:
            raise CanonicalJSONError("finding message identifier is invalid")
        require_digest(self.subject_id)
        canonical_bytes(self.parameters)
        if not isinstance(self.integrity_failure, bool):
            raise CanonicalJSONError("integrity_failure must be Boolean")


def finding_payload(finding: Finding) -> JsonObject:
    return {
        "code": finding.code,
        "integrity_failure": finding.integrity_failure,
        "message_id": finding.message_id,
        "parameters": finding.parameters,
        "subject_id": finding.subject_id,
        "verdict": finding.verdict.value,
    }

