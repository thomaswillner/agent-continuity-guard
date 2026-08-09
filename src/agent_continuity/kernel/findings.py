"""Normalized non-PASS findings."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .canonical import CanonicalJSONError, canonical_bytes, canonical_loads
from .evaluation import Verdict
from .model import JsonObject, RecordId
from .records import require_digest

_CODE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_MESSAGE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,191}$")


@dataclass(frozen=True, slots=True, init=False)
class Finding:
    code: str
    verdict: Verdict
    subject_id: RecordId
    message_id: str
    integrity_failure: bool
    _parameters_bytes: bytes = field(repr=False)

    def __init__(
        self,
        code: str,
        verdict: Verdict,
        subject_id: RecordId,
        message_id: str,
        parameters: JsonObject,
        integrity_failure: bool = False,
    ) -> None:
        if type(code) is not str or _CODE_RE.fullmatch(code) is None:
            raise CanonicalJSONError("finding code is invalid")
        if type(verdict) is not Verdict:
            raise CanonicalJSONError("finding verdict is invalid")
        if type(message_id) is not str or _MESSAGE_RE.fullmatch(message_id) is None:
            raise CanonicalJSONError("finding message identifier is invalid")
        require_digest(subject_id)
        if type(parameters) is not dict:
            raise CanonicalJSONError("finding parameters must be an exact JSON object")
        parameters_bytes = canonical_bytes(parameters)
        if type(integrity_failure) is not bool:
            raise CanonicalJSONError("integrity_failure must be Boolean")
        object.__setattr__(self, "code", code)
        object.__setattr__(self, "verdict", verdict)
        object.__setattr__(self, "subject_id", subject_id)
        object.__setattr__(self, "message_id", message_id)
        object.__setattr__(self, "integrity_failure", integrity_failure)
        object.__setattr__(self, "_parameters_bytes", parameters_bytes)

    @property
    def parameters(self) -> JsonObject:
        """Return a fresh copy of immutable canonical parameter bytes."""

        return canonical_loads(self._parameters_bytes)


def finding_payload(finding: Finding) -> JsonObject:
    return {
        "code": finding.code,
        "integrity_failure": finding.integrity_failure,
        "message_id": finding.message_id,
        "parameters": finding.parameters,
        "subject_id": finding.subject_id,
        "verdict": finding.verdict.value,
    }
