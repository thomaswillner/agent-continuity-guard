"""Strict TOML authoring compiled into canonical Policy/v1 records."""

from __future__ import annotations

import os
import stat
import tomllib
from contextlib import suppress
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import Final, TypeVar

from agent_continuity.kernel.canonical import (
    CanonicalJSONError,
    canonical_bytes,
    digest_bytes,
    record_id,
)
from agent_continuity.kernel.evaluation import Profile, Verdict
from agent_continuity.kernel.model import (
    ADAPTER_CAPABILITY_VOCABULARY_V1,
    DETECTOR_CODE_VOCABULARY_V1,
    RESOURCE_LIMIT_MAXIMA_V1,
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
_MAX_POLICY_PATH_BYTES: Final = 32 * 1024
_MAX_POLICY_PATH_COMPONENT_BYTES: Final = 255
_LIMIT_MAXIMA: Final = dict(RESOURCE_LIMIT_MAXIMA_V1)
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

    exit_code: Final = 2


@dataclass(frozen=True, slots=True)
class LoadedPolicy:
    compiled: CompiledPolicyV1
    source: str
    source_digest: Digest


def _absolute_components(path: Path, *, allow_root: bool) -> tuple[str, ...]:
    if not isinstance(path, Path):
        raise PolicyRequestError("policy path is invalid")
    raw = str(path)
    encoded: bytes | None = None
    with suppress(UnicodeEncodeError):
        encoded = raw.encode("utf-8", errors="strict")
    if (
        encoded is None
        or len(encoded) > _MAX_POLICY_PATH_BYTES
        or not path.is_absolute()
        or path.anchor != os.sep
        or not raw
        or any(item < 0x20 for item in encoded)
    ):
        raise PolicyRequestError("policy path is invalid")
    components = path.parts[1:]
    if (not allow_root and not components) or any(
        component in {"", ".", ".."} for component in components
    ):
        raise PolicyRequestError("policy path is invalid")
    component_bytes: list[bytes] = []
    for component in components:
        try:
            value = component.encode("utf-8", errors="strict")
        except UnicodeEncodeError:
            value = b""
        component_bytes.append(value)
    if any(
        not value or len(value) > _MAX_POLICY_PATH_COMPONENT_BYTES
        for value in component_bytes
    ):
        raise PolicyRequestError("policy path is invalid")
    canonical = os.sep + os.sep.join(components) if components else os.sep
    if raw != canonical:
        raise PolicyRequestError("policy path is noncanonical")
    return components


def _file_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    if type(no_follow) is not int or no_follow <= 0:
        raise PolicyRequestError("no-follow policy reads are unsupported")
    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= no_follow
    return flags


def _directory_flags() -> int:
    flags = _file_flags()
    flags |= getattr(os, "O_DIRECTORY", 0)
    return flags


def _safe_close(descriptor: int) -> None:
    with suppress(OSError):
        os.close(descriptor)


def _open_directory_component(parent_fd: int, component: str) -> int:
    descriptor: int | None = None
    with suppress(OSError):
        descriptor = os.open(
            component,
            _directory_flags(),
            dir_fd=parent_fd,
        )
    if descriptor is None:
        raise PolicyRequestError("policy path component is unavailable")
    metadata: os.stat_result | None = None
    with suppress(OSError):
        metadata = os.fstat(descriptor)
    if metadata is None or not stat.S_ISDIR(metadata.st_mode):
        _safe_close(descriptor)
        raise PolicyRequestError("policy path component is invalid")
    return descriptor


def _walk_absolute_directories(components: tuple[str, ...]) -> int:
    descriptor: int | None = None
    with suppress(OSError):
        descriptor = os.open(os.sep, _directory_flags())
    if descriptor is None:
        raise PolicyRequestError("policy root descriptor is unavailable")
    for component in components:
        try:
            next_descriptor = _open_directory_component(descriptor, component)
        except PolicyRequestError:
            _safe_close(descriptor)
            raise
        _safe_close(descriptor)
        descriptor = next_descriptor
    return descriptor


def _open_absolute_file(components: tuple[str, ...]) -> int:
    parent_fd = _walk_absolute_directories(components[:-1])
    descriptor: int | None = None
    try:
        with suppress(OSError):
            descriptor = os.open(
                components[-1],
                _file_flags(),
                dir_fd=parent_fd,
            )
    finally:
        _safe_close(parent_fd)
    if descriptor is None:
        raise PolicyRequestError("explicit policy source is unavailable")
    return descriptor


def _read_fd(descriptor: int) -> bytes:
    before: os.stat_result | None = None
    with suppress(OSError):
        before = os.fstat(descriptor)
    if before is None:
        raise PolicyRequestError("policy source could not be observed")
    if not stat.S_ISREG(before.st_mode):
        raise PolicyRequestError("policy source is not a regular file")
    chunks: list[bytes] = []
    total = 0
    read_failed = False
    while True:
        chunk: bytes | None = None
        try:
            chunk = os.read(descriptor, min(1024 * 1024, _MAX_POLICY_BYTES + 1 - total))
        except OSError:
            read_failed = True
        if read_failed:
            break
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > _MAX_POLICY_BYTES:
            raise PolicyRequestError("policy source exceeded byte limit")
    if read_failed:
        raise PolicyRequestError("policy source could not be read")
    after: os.stat_result | None = None
    with suppress(OSError):
        after = os.fstat(descriptor)
    if after is None:
        raise PolicyRequestError("policy source could not be observed")
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


def _read_explicit(components: tuple[str, ...]) -> bytes:
    descriptor = _open_absolute_file(components)
    try:
        return _read_fd(descriptor)
    finally:
        _safe_close(descriptor)


def _read_target(components: tuple[str, ...]) -> bytes | None:
    root_fd = _walk_absolute_directories(components)
    descriptor: int | None = None
    missing = False
    try:
        try:
            descriptor = os.open("acg.toml", _file_flags(), dir_fd=root_fd)
        except FileNotFoundError:
            missing = True
        except OSError:
            pass
    finally:
        _safe_close(root_fd)
    if missing:
        return None
    if descriptor is None:
        raise PolicyRequestError("target policy source is unavailable")
    try:
        return _read_fd(descriptor)
    finally:
        _safe_close(descriptor)


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
    converted: _EnumT | None = None
    with suppress(ValueError):
        converted = enum_type(text)
    if converted is None:
        raise PolicyRequestError(f"{field} is unsupported")
    return converted


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
    valid = True
    try:
        for item in values:
            require_digest(item)
    except CanonicalJSONError:
        valid = False
    if not valid:
        raise PolicyRequestError(f"{field} contains invalid record identifiers")
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
    if any(key not in DETECTOR_CODE_VOCABULARY_V1 for key in value):
        raise PolicyRequestError("severity_by_code contains unsupported identifiers")
    result: list[tuple[str, Verdict]] = []
    for key, raw in value.items():
        text = _exact_string(raw, field="severity_by_code")
        verdict: Verdict | None = None
        with suppress(ValueError):
            verdict = Verdict(text)
        if verdict is None:
            raise PolicyRequestError("severity_by_code is unsupported")
        if verdict not in {Verdict.WARN, Verdict.BLOCK}:
            raise PolicyRequestError("severity_by_code cannot configure this verdict")
        result.append((key, verdict))
    return tuple(sorted(result, key=lambda item: item[0]))


def _parse(authoring: bytes) -> dict[str, object]:
    loaded: dict[str, object] | None = None
    with suppress(UnicodeDecodeError, tomllib.TOMLDecodeError):
        loaded = tomllib.loads(authoring.decode("utf-8", errors="strict"))
    if loaded is None:
        raise PolicyRequestError("policy authoring is invalid TOML")
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
        allowed=ADAPTER_CAPABILITY_VOCABULARY_V1,
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
        allowed=DETECTOR_CODE_VOCABULARY_V1,
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

    target_components = _absolute_components(target, allow_root=True)
    if explicit is not None:
        explicit_components = _absolute_components(explicit, allow_root=False)
        authoring = _read_explicit(explicit_components)
        source = "explicit"
    else:
        target_authoring = _read_target(target_components)
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


def load_target_policy(authoring: bytes | None) -> LoadedPolicy:
    """Compile policy bytes observed through an admitted target adapter."""

    if authoring is not None and type(authoring) is not bytes:
        raise PolicyRequestError("target policy authoring is invalid")
    selected = _BUILTIN_BYTES if authoring is None else authoring
    compiled = _compile(selected)
    return LoadedPolicy(
        compiled=compiled,
        source="builtin" if authoring is None else "target",
        source_digest=compiled.authoring_digest,
    )


def apply_facade_overrides(
    loaded: LoadedPolicy,
    *,
    profile: Profile | None,
    promotion_mode: PromotionMode | None,
) -> LoadedPolicy:
    """Validate and recompile explicit facade overrides into Policy/v1 identity."""

    if type(loaded) is not LoadedPolicy:
        raise PolicyRequestError("loaded policy is invalid")
    if profile is not None and type(profile) is not Profile:
        raise PolicyRequestError("facade profile override is invalid")
    if promotion_mode is not None and type(promotion_mode) is not PromotionMode:
        raise PolicyRequestError("facade promotion override is invalid")
    if profile is None and promotion_mode is None:
        return loaded

    selected_profile = loaded.compiled.profile if profile is None else profile
    selected_promotion = (
        loaded.compiled.promotion_mode
        if promotion_mode is None
        else promotion_mode
    )
    authoring_digest = digest_bytes(
        canonical_bytes(
            {
                "base_policy_id": loaded.compiled.policy_id,
                "profile": None if profile is None else profile.value,
                "promotion_mode": (
                    None if promotion_mode is None else promotion_mode.value
                ),
                "schema": "PolicyFacadeOverride/v1",
            }
        )
    )
    base = loaded.compiled
    placeholder = CompiledPolicyV1(
        policy_id=RecordId("sha256:" + "0" * 64),
        authoring_digest=authoring_digest,
        profile=selected_profile,
        promotion_mode=selected_promotion,
        limits=base.limits,
        required_adapter_capabilities=base.required_adapter_capabilities,
        max_assignment_authority=base.max_assignment_authority,
        approval_operator_ids=base.approval_operator_ids,
        rollback_operator_ids=base.rollback_operator_ids,
        evidence_expiry_seconds=base.evidence_expiry_seconds,
        enabled_detectors=base.enabled_detectors,
        severity_by_code=base.severity_by_code,
    )
    compiled = CompiledPolicyV1(
        policy_id=record_id("Policy", "v1", policy_payload(placeholder)),
        authoring_digest=authoring_digest,
        profile=selected_profile,
        promotion_mode=selected_promotion,
        limits=base.limits,
        required_adapter_capabilities=base.required_adapter_capabilities,
        max_assignment_authority=base.max_assignment_authority,
        approval_operator_ids=base.approval_operator_ids,
        rollback_operator_ids=base.rollback_operator_ids,
        evidence_expiry_seconds=base.evidence_expiry_seconds,
        enabled_detectors=base.enabled_detectors,
        severity_by_code=base.severity_by_code,
    )
    return LoadedPolicy(
        compiled=compiled,
        source=f"{loaded.source}+facade",
        source_digest=loaded.source_digest,
    )


def render_policy_template() -> JsonObject:
    """Return a canonical JSON-safe template; caller deliberately joins lines."""

    return {
        "authoring_digest": digest_bytes(_BUILTIN_BYTES),
        "schema": "PolicyTemplate/v1",
        "toml_lines": list(_TEMPLATE_LINES),
    }
