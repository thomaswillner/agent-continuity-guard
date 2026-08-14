"""Public, canonical-JSON command line boundary for ACG."""

from __future__ import annotations

import argparse
import contextlib
import errno
import os
import stat
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import NoReturn, cast

from agent_continuity.adapters import SystemClock
from agent_continuity.api import (
    AlreadyInitialized,
    Continuity,
    ContinuityRequestError,
    TransitionRefused,
)
from agent_continuity.capture import (
    CaptureRequestError,
    CaptureUnknownError,
    GitTargetAdapter,
)
from agent_continuity.kernel.audit import (
    AuditAnchorV1,
    audit_anchor_payload,
    audit_verification_payload,
)
from agent_continuity.kernel.canonical import CanonicalJSONError, canonical_loads
from agent_continuity.kernel.checkpoint import verification_result_payload
from agent_continuity.kernel.model import JsonObject, LogicalTime, RecordId
from agent_continuity.kernel.records import checkpoint_receipt_payload
from agent_continuity.output import ErrorRecord, canonical_output, error_payload
from agent_continuity.policy import PolicyRequestError, render_policy_template
from agent_continuity.store import StoreIntegrityError, StoreValidationError
from agent_continuity.store.paths import (
    StatePathError,
    assert_external_state,
    resolve_state_home,
)


class CLIRequestError(ValueError):
    """Invalid command input whose details must not cross the CLI boundary."""


_UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS: frozenset[int] = frozenset(
    value
    for value in (getattr(errno, "EINVAL", None), getattr(errno, "ENOTSUP", None))
    if type(value) is int
)


class _Parser(argparse.ArgumentParser):
    def error(self, _message: str) -> NoReturn:
        raise CLIRequestError("invalid command request")


def _common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--target", required=True)
    parser.add_argument("--state-home", required=True)
    parser.add_argument("--session-key", default="default")
    parser.add_argument("--policy")


def _parser() -> argparse.ArgumentParser:
    parser = _Parser(prog="acg", add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)

    policy_template = commands.add_parser("policy-template", add_help=False)
    policy_template.set_defaults(handler="policy-template")

    initialize = commands.add_parser("init", add_help=False)
    _common_arguments(initialize)
    initialize.add_argument("--goal", required=True)
    initialize.add_argument("--criterion", action="append", default=[])
    initialize.add_argument("--instruction", action="append", default=[])
    initialize.set_defaults(handler="init")

    checkpoint = commands.add_parser("checkpoint", add_help=False)
    _common_arguments(checkpoint)
    checkpoint.add_argument("--reason")
    checkpoint.set_defaults(handler="checkpoint")

    verify = commands.add_parser("verify", add_help=False)
    _common_arguments(verify)
    verify.add_argument("--checkpoint", default="latest")
    verify.set_defaults(handler="verify")

    verify_audit = commands.add_parser("verify-audit", add_help=False)
    _common_arguments(verify_audit)
    verify_audit.add_argument("--anchor")
    verify_audit.set_defaults(handler="verify-audit")

    audit_anchor = commands.add_parser("audit-anchor", add_help=False)
    anchor_commands = audit_anchor.add_subparsers(
        dest="anchor_command", required=True
    )
    export = anchor_commands.add_parser("export", add_help=False)
    _common_arguments(export)
    export.add_argument("--output", required=True)
    export.add_argument("--label")
    export.set_defaults(handler="audit-anchor-export")
    return parser


def _continuity(arguments: argparse.Namespace) -> Continuity:
    return Continuity.open(
        arguments.target,
        state_home=arguments.state_home,
        policy=arguments.policy,
        session_key=arguments.session_key,
    )


def _load_anchor(value: str | None) -> AuditAnchorV1 | None:
    if value is None:
        return None
    try:
        raw = Path(value).read_bytes()
        parsed = canonical_loads(raw)
        if canonical_output(parsed) != raw:
            raise ValueError("anchor bytes are noncanonical")
        if set(parsed) != {
            "audit_head_id",
            "audit_sequence",
            "created_at",
            "label",
            "store_id",
        }:
            raise ValueError("anchor object is invalid")
        return AuditAnchorV1(
            audit_head_id=RecordId(cast(str, parsed["audit_head_id"])),
            audit_sequence=cast(int, parsed["audit_sequence"]),
            created_at=LogicalTime(cast(str, parsed["created_at"])),
            label=cast(str | None, parsed["label"]),
            store_id=cast(str, parsed["store_id"]),
        )
    except (CanonicalJSONError, OSError, TypeError, ValueError) as error:
        raise CLIRequestError("invalid audit anchor") from error


def _directory_flags() -> int:
    no_follow = getattr(os, "O_NOFOLLOW", None)
    directory = getattr(os, "O_DIRECTORY", None)
    if type(no_follow) is not int or type(directory) is not int:
        raise CLIRequestError("safe anchor output is unsupported")
    return os.O_RDONLY | no_follow | directory | getattr(os, "O_CLOEXEC", 0)


def _safe_close(descriptor: int) -> None:
    if descriptor >= 0:
        with contextlib.suppress(OSError):
            os.close(descriptor)


def _open_pinned_directory(path: Path) -> int:
    if not path.is_absolute() or any(part in {".", ".."} for part in path.parts):
        raise CLIRequestError("anchor directory is invalid")
    descriptor = os.open(os.path.sep, _directory_flags())
    try:
        for component in path.parts[1:]:
            next_descriptor = os.open(
                component,
                _directory_flags(),
                dir_fd=descriptor,
            )
            _safe_close(descriptor)
            descriptor = next_descriptor
        return descriptor
    except OSError as error:
        _safe_close(descriptor)
        raise CLIRequestError("anchor directory is unavailable") from error


def _directory_identity(descriptor: int) -> tuple[int, int]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        raise CLIRequestError("anchor directory is invalid")
    return metadata.st_dev, metadata.st_ino


def _ancestor_identities(descriptor: int) -> frozenset[tuple[int, int]]:
    current = os.dup(descriptor)
    result: set[tuple[int, int]] = set()
    try:
        while True:
            identity = _directory_identity(current)
            if identity in result:
                return frozenset(result)
            result.add(identity)
            parent = os.open("..", _directory_flags(), dir_fd=current)
            _safe_close(current)
            current = parent
    except OSError as error:
        raise CLIRequestError("anchor directory ancestry is unavailable") from error
    finally:
        _safe_close(current)


def _fsync_directory(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        if error.errno in _UNSUPPORTED_DIRECTORY_FSYNC_ERRNOS:
            return
        raise


def _cleanup_anchor_output(parent_fd: int, name: str) -> None:
    try:
        os.unlink(name, dir_fd=parent_fd)
    except FileNotFoundError:
        return
    _fsync_directory(parent_fd)


def _safe_anchor_output(
    output: str,
    *,
    target: Path,
    git_directory: Path | None,
    state_home: Path,
    contents: bytes,
) -> None:
    candidate = Path(output)
    if not candidate.is_absolute() or candidate.name in {"", ".", ".."}:
        raise CLIRequestError("anchor output is invalid")
    parent_fd = -1
    output_fd = -1
    protected_fds: list[int] = []
    created = False
    try:
        parent = candidate.parent.resolve(strict=True)
        if not parent.is_dir():
            raise OSError("anchor parent is invalid")
        protected_roots: tuple[Path, ...] = (target, state_home)
        if git_directory is not None:
            protected_roots += (git_directory,)
        protected_fds = [
            _open_pinned_directory(root.resolve(strict=True))
            for root in protected_roots
        ]
        protected = frozenset(_directory_identity(item) for item in protected_fds)
        parent_fd = _open_pinned_directory(parent)
        if _ancestor_identities(parent_fd) & protected:
            raise CLIRequestError("anchor output overlaps protected state")
        assert_external_state(target, git_directory, state_home)
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_CLOEXEC", 0)
        no_follow = getattr(os, "O_NOFOLLOW", None)
        if type(no_follow) is not int:
            raise CLIRequestError("safe anchor output is unsupported")
        output_fd = os.open(candidate.name, flags | no_follow, 0o600, dir_fd=parent_fd)
        created = True
        metadata = os.fstat(output_fd)
        if not stat.S_ISREG(metadata.st_mode):
            raise CLIRequestError("anchor output is invalid")
        os.fchmod(output_fd, 0o600)
        offset = 0
        while offset < len(contents):
            written = os.write(output_fd, contents[offset:])
            if written <= 0:
                raise OSError("anchor output write did not advance")
            offset += written
        os.fsync(output_fd)
        _safe_close(output_fd)
        output_fd = -1
        _fsync_directory(parent_fd)
    except (CLIRequestError, OSError, RuntimeError, StatePathError) as error:
        failure: BaseException = error
        if created:
            _safe_close(output_fd)
            output_fd = -1
            try:
                _cleanup_anchor_output(parent_fd, candidate.name)
            except OSError as cleanup_error:
                failure = cleanup_error
        if isinstance(failure, CLIRequestError):
            raise failure from None
        raise CLIRequestError("anchor output is unavailable") from failure
    finally:
        _safe_close(output_fd)
        _safe_close(parent_fd)
        for descriptor in protected_fds:
            _safe_close(descriptor)


def _audit_payload(
    continuity: Continuity,
    *,
    anchor: AuditAnchorV1 | None,
) -> JsonObject:
    with continuity._open_session_store() as store:
        verification = store.verify_audit(anchor)
    if not verification.valid or (
        anchor is not None and not verification.supplied_anchor_matched
    ):
        raise StoreIntegrityError("audit verification is invalid")
    return audit_verification_payload(verification)


def _export_anchor(arguments: argparse.Namespace, continuity: Continuity) -> JsonObject:
    try:
        with continuity._open_session_store() as store:
            anchor = store.make_anchor(
                created_at=SystemClock().now(),
                label=arguments.label,
            )
    except ValueError as error:
        raise CLIRequestError("audit anchor label is invalid") from error
    payload = audit_anchor_payload(anchor)
    target = Path(arguments.target).resolve(strict=True)
    with GitTargetAdapter(target) as adapter:
        git_directory = adapter.git_common_directory
    _safe_anchor_output(
        arguments.output,
        target=target,
        git_directory=git_directory,
        state_home=resolve_state_home(arguments.state_home),
        contents=canonical_output(payload),
    )
    return payload


def _run(arguments: argparse.Namespace) -> JsonObject:
    handler = arguments.handler
    if handler == "policy-template":
        return render_policy_template()
    continuity = _continuity(arguments)
    if handler == "init":
        return checkpoint_receipt_payload(
            continuity.initialize(
                arguments.goal,
                arguments.criterion,
                instruction_paths=arguments.instruction,
            )
        )
    if handler == "checkpoint":
        return checkpoint_receipt_payload(continuity.checkpoint(arguments.reason))
    if handler == "verify":
        return verification_result_payload(continuity.verify(arguments.checkpoint))
    if handler == "verify-audit":
        return _audit_payload(continuity, anchor=_load_anchor(arguments.anchor))
    if handler == "audit-anchor-export":
        return _export_anchor(arguments, continuity)
    raise CLIRequestError("command is unavailable")


def _emit(payload: JsonObject) -> None:
    sys.stdout.buffer.write(canonical_output(payload))


def main(argv: Sequence[str] | None = None) -> int:
    try:
        arguments = _parser().parse_args(argv)
        _emit(_run(arguments))
        return 0
    except (
        CLIRequestError,
        AlreadyInitialized,
        CaptureRequestError,
        ContinuityRequestError,
        PolicyRequestError,
        StatePathError,
    ):
        _emit(
            error_payload(
                ErrorRecord("request", "request_invalid", "acg.request.invalid")
            )
        )
        return 2
    except (CaptureUnknownError, TransitionRefused):
        _emit(
            error_payload(
                ErrorRecord(
                    "transition",
                    "protected_transition_refused",
                    "acg.transition.refused",
                )
            )
        )
        return 1
    except (StoreIntegrityError, StoreValidationError):
        _emit(
            error_payload(
                ErrorRecord(
                    "integrity", "store_integrity_failed", "acg.store.integrity"
                )
            )
        )
        return 3
    except Exception:
        _emit(
            error_payload(
                ErrorRecord("internal", "internal_failure", "acg.internal.failure")
            )
        )
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
