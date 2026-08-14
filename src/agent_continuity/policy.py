"""Strict TOML authoring compiled into canonical Policy/v1 records."""

from __future__ import annotations

import os
import stat
import tomllib
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, TypeVar

from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    digest_bytes,
    record_id,
)
from agent_continuity.kernel.evaluation import Profile, Verdict
from agent_continuity.kernel.model import (
    AssignmentAuthority,
    Digest,
    JsonObject,
    PromotionMode,
    RecordId,
    ResourceLimitsV1,
)
from agent_continuity.kernel.records import (
    CompiledPolicyV1,
    policy_payload,
    require_digest,
)

_MAX_POLICY_BYTES: Final = 8 * 1024 * 1024
_CAPABILITIES: Final = frozenset(
    {
        "atomic_snapshot",
        "descriptor_pinned_reads",
        "git_immutable_objects",
        "git_network_disabled",
        "windows_reparse_protection",
    }
)
_DETECTORS: Final = frozenset({"capture.unstable", "target.dirty"})
_LIMIT_MAXIMA: Final = {
    "max_paths": 250_000,
    "max_file_bytes": 1_073_741_824,
    "max_aggregate_bytes": 21_474_836_480,
    "max_analyzer_text_bytes": 4_194_304,
    "max_external_json_bytes": 8_388_608,
}
_TOP_LEVEL_KEYS: Final = frozenset(
    {
        "version",
        "profile",
        "promotion_mode",
        "limits",
        "required_adapter_capabilities",
        "max_assignment_authority",
        "approval_operator_ids",
        "rollback_operator_ids",
        "evidence_expiry_seconds",
        "enabled_detectors",
        "severity_by_code",
    }
)
_TEMPLATE_LINES: Final = (
    "version = 1",
    'profile = "guard"',
    'promotion_mode = "automatic"',
    'max_assignment_authority = "read_only"',
    "approval_operator_ids = []",
    "rollback_operator_ids = []",
    "required_adapter_capabilities = []",
    "evidence_expiry_seconds = 3600",
    'enabled_detectors = ["capture.unstable", "target.dirty"]',
    'severity_by_code = {"capture.unstable" = "block", "target.dirty" = "block"}',
    "",
    "[limits]",
    "max_paths = 250000",
    "max_file_bytes = 1073741824",
    "max_aggregate_bytes = 21474836480",
    "max_analyzer_text_bytes = 4194304",
    "max_external_json_bytes = 8388608",
)
_BUILTIN_BYTES: Final = "\n".join(_TEMPLATE_LINES).encode("utf-8")
_EnumT = TypeVar("_EnumT", bound=StrEnum)


class PolicyError(RuntimeError):
    """Base class for sanitized policy failures."""


class PolicyRequestError(PolicyError):
    """Policy request or authoring is invalid."""


@dataclass(frozen=True, slots=True)
class LoadedPolicy:
    compiled: CompiledPolicyV1
    source: str
    source_digest: Digest


def _validated_absolute(path: Path, *, target: bool) -> Path:
    if not isinstance(path, Path):
        raise PolicyRequestError("policy path is invalid")
    raw = str(path)
    try:
        raw.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise PolicyRequestError("policy path is invalid") from error
    if not path.is_absolute() or not raw or any(ord(item) < 0x20 for item in raw):
        raise PolicyRequestError("policy path is invalid")
    if target:
        try:
            metadata = path.stat()
        except OSError as error:
            raise PolicyRequestError("target policy root is unavailable") from error
        if not stat.S_ISDIR(metadata.st_mode):
            raise PolicyRequestError("target policy root is unavailable")
    return path


def _file_flags() -> int:
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    return flags


def _read_fd(descriptor: int) -> bytes:
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PolicyRequestError("policy source is not a regular file")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_POLICY_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > _MAX_POLICY_BYTES:
                raise PolicyRequestError("policy source exceeded byte limit")
        after = os.fstat(descriptor)
    except PolicyRequestError:
        raise
    except OSError as error:
        raise PolicyRequestError("policy source could not be read") from error
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or total != before.st_size:
        raise PolicyRequestError("policy source changed during capture")
    return b"".join(chunks)


def _read_explicit(path: Path) -> bytes:
    try:
        descriptor = os.open(path, _file_flags())
    except OSError as error:
        raise PolicyRequestError("explicit policy source is unavailable") from error
    try:
        return _read_fd(descriptor)
    finally:
        os.close(descriptor)


def _read_target(target: Path) -> bytes | None:
    directory_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    directory_flags |= getattr(os, "O_DIRECTORY", 0)
    directory_flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        root_fd = os.open(target, directory_flags)
    except OSError as error:
        raise PolicyRequestError("target policy root is unavailable") from error
    try:
        try:
            descriptor = os.open("acg.toml", _file_flags(), dir_fd=root_fd)
        except FileNotFoundError:
            return None
        except OSError as error:
            raise PolicyRequestError("target policy source is unavailable") from error
        try:
            return _read_fd(descriptor)
        finally:
            os.close(descriptor)
    finally:
        os.close(root_fd)


def _exact_string(value: object, *, field: str) -> str:
    if type(value) is not str:
        raise PolicyRequestError(f"{field} has invalid type")
    return value


def _enum(
    value: object,
    enum_type: type[_EnumT],
    *,
    field: str,
) -> _EnumT:
    text = _exact_string(value, field=field)
    try:
        return enum_type(text)
    except ValueError as error:
        raise PolicyRequestError(f"{field} is unsupported") from error


def _string_tuple(
    value: object,
    *,
    field: str,
    allowed: frozenset[str] | None = None,
    max_items: int | None = None,
) -> tuple[str, ...]:
    if type(value) is not list or any(type(item) is not str for item in value):
        raise PolicyRequestError(f"{field} has invalid type")
    values = tuple(value)
    if max_items is not None and len(values) > max_items:
        raise PolicyRequestError(f"{field} exceeded item limit")
    if len(set(values)) != len(values):
        raise PolicyRequestError(f"{field} contains duplicates")
    if allowed is not None and any(item not in allowed for item in values):
        raise PolicyRequestError(f"{field} contains unsupported identifiers")
    return tuple(sorted(values))


def _operator_ids(value: object, *, field: str) -> tuple[RecordId, ...]:
    values = _string_tuple(value, field=field, max_items=1024)
    try:
        for item in values:
            require_digest(item)
    except CanonicalJSONError as error:
        raise PolicyRequestError(
            f"{field} contains invalid record identifiers"
        ) from error
    return tuple(RecordId(item) for item in values)


def _positive_integer(value: object, *, field: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 1 or (maximum is not None and value > maximum):
        raise PolicyRequestError(f"{field} is outside its compile-time bounds")
    return value


def _limits(value: object) -> ResourceLimitsV1:
    if type(value) is not dict or set(value) - set(_LIMIT_MAXIMA):
        raise PolicyRequestError("limits contains unknown fields")
    defaults = _LIMIT_MAXIMA
    compiled = {
        key: _positive_integer(value.get(key, default), field=key, maximum=default)
        for key, default in defaults.items()
    }
    if compiled["max_analyzer_text_bytes"] > compiled["max_file_bytes"]:
        raise PolicyRequestError("limits have an invalid analyzer relationship")
    if compiled["max_file_bytes"] > compiled["max_aggregate_bytes"]:
        raise PolicyRequestError("limits have an invalid aggregate relationship")
    return ResourceLimitsV1(
        max_paths=compiled["max_paths"],
        max_file_bytes=compiled["max_file_bytes"],
        max_aggregate_bytes=compiled["max_aggregate_bytes"],
        max_analyzer_text_bytes=compiled["max_analyzer_text_bytes"],
        max_external_json_bytes=compiled["max_external_json_bytes"],
    )


def _severity(value: object) -> tuple[tuple[str, Verdict], ...]:
    if type(value) is not dict or any(type(key) is not str for key in value):
        raise PolicyRequestError("severity_by_code has invalid type")
    if any(key not in _DETECTORS for key in value):
        raise PolicyRequestError("severity_by_code contains unsupported identifiers")
    result: list[tuple[str, Verdict]] = []
    for key, raw in value.items():
        text = _exact_string(raw, field="severity_by_code")
        try:
            verdict = Verdict(text)
        except ValueError as error:
            raise PolicyRequestError("severity_by_code is unsupported") from error
        if verdict not in {Verdict.WARN, Verdict.BLOCK}:
            raise PolicyRequestError("severity_by_code cannot configure this verdict")
        result.append((key, verdict))
    return tuple(sorted(result, key=lambda item: item[0]))


def _parse(authoring: bytes) -> dict[str, object]:
    try:
        loaded = tomllib.loads(authoring.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise PolicyRequestError("policy authoring is invalid TOML") from error
    if type(loaded) is not dict:
        raise PolicyRequestError("policy authoring must be a table")
    if set(loaded) - set(_TOP_LEVEL_KEYS):
        raise PolicyRequestError("policy authoring contains unknown fields")
    return loaded


def _compile(authoring: bytes) -> CompiledPolicyV1:
    loaded = _parse(authoring)
    if (
        "version" not in loaded
        or type(loaded["version"]) is not int
        or loaded["version"] != 1
    ):
        raise PolicyRequestError("policy version is unsupported")
    profile = _enum(loaded.get("profile", "guard"), Profile, field="profile")
    promotion = _enum(
        loaded.get("promotion_mode", "automatic"),
        PromotionMode,
        field="promotion_mode",
    )
    authority = _enum(
        loaded.get("max_assignment_authority", "read_only"),
        AssignmentAuthority,
        field="max_assignment_authority",
    )
    limits = _limits(loaded.get("limits", {}))
    capabilities = _string_tuple(
        loaded.get("required_adapter_capabilities", []),
        field="required_adapter_capabilities",
        allowed=_CAPABILITIES,
    )
    approval_ids = _operator_ids(
        loaded.get("approval_operator_ids", []), field="approval_operator_ids"
    )
    rollback_ids = _operator_ids(
        loaded.get("rollback_operator_ids", []), field="rollback_operator_ids"
    )
    expiry = _positive_integer(
        loaded.get("evidence_expiry_seconds", 3600),
        field="evidence_expiry_seconds",
    )
    detectors = _string_tuple(
        loaded.get("enabled_detectors", ["capture.unstable", "target.dirty"]),
        field="enabled_detectors",
        allowed=_DETECTORS,
    )
    raw_severity = loaded.get("severity_by_code")
    if raw_severity is None:
        severity = tuple((code, Verdict.BLOCK) for code in detectors)
    else:
        severity = _severity(raw_severity)
    if {code for code, _verdict in severity} != set(detectors):
        raise PolicyRequestError("severity_by_code must cover enabled detectors")
    authoring_digest = digest_bytes(authoring)
    placeholder = CompiledPolicyV1(
        policy_id=RecordId("sha256:" + "0" * 64),
        authoring_digest=authoring_digest,
        profile=profile,
        promotion_mode=promotion,
        limits=limits,
        required_adapter_capabilities=capabilities,
        max_assignment_authority=authority,
        approval_operator_ids=approval_ids,
        rollback_operator_ids=rollback_ids,
        evidence_expiry_seconds=expiry,
        enabled_detectors=detectors,
        severity_by_code=severity,
    )
    identity = record_id("Policy", "v1", policy_payload(placeholder))
    return CompiledPolicyV1(
        policy_id=identity,
        authoring_digest=authoring_digest,
        profile=profile,
        promotion_mode=promotion,
        limits=limits,
        required_adapter_capabilities=capabilities,
        max_assignment_authority=authority,
        approval_operator_ids=approval_ids,
        rollback_operator_ids=rollback_ids,
        evidence_expiry_seconds=expiry,
        enabled_detectors=detectors,
        severity_by_code=severity,
    )


def load_policy(*, target: Path, explicit: Path | None) -> LoadedPolicy:
    """Load explicit, target-root, or built-in policy without target writes."""

    target = _validated_absolute(target, target=True)
    if explicit is not None:
        explicit = _validated_absolute(explicit, target=False)
        authoring = _read_explicit(explicit)
        source = "explicit"
    else:
        target_authoring = _read_target(target)
        if target_authoring is None:
            authoring = _BUILTIN_BYTES
            source = "builtin"
        else:
            authoring = target_authoring
            source = "target"
    compiled = _compile(authoring)
    return LoadedPolicy(
        compiled=compiled,
        source=source,
        source_digest=compiled.authoring_digest,
    )


def render_policy_template() -> JsonObject:
    """Return a canonical JSON-safe template; caller deliberately joins lines."""

    return {
        "authoring_digest": digest_bytes(_BUILTIN_BYTES),
        "schema": "PolicyTemplate/v1",
        "toml_lines": list(_TEMPLATE_LINES),
    }
