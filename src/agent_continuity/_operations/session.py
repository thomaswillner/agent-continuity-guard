"""Private continuity session discovery, opening, selection, and verified loading."""

from __future__ import annotations

import os
import re
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from agent_continuity.adapters import Clock
from agent_continuity.capture import CaptureSnapshot, TargetAdapter
from agent_continuity.kernel.canonical import CanonicalJSONError, canonical_loads
from agent_continuity.kernel.checkpoint import (
    checkpoint_from_record,
    instruction_paths_from_record,
)
from agent_continuity.kernel.citation import CitationV1
from agent_continuity.kernel.evaluation import Profile
from agent_continuity.kernel.evidence import EvidenceV1, InvalidatorKind
from agent_continuity.kernel.model import PromotionMode, RecordId
from agent_continuity.kernel.records import (
    ActorV1,
    CheckpointV1,
    GoalV1,
    InitializationIntentV1,
    RecordSchemaError,
    build_initialization_intent,
    build_ruleset,
    decode_record,
    make_record,
    producer_identity_payload,
)
from agent_continuity.policy import LoadedPolicy
from agent_continuity.store import (
    SQLiteStateStore,
    StoreIntegrityError,
    StoreValidationError,
    open_external_state_root,
)
from agent_continuity.store.paths import StatePathError

_DATABASE_LOCKS: dict[tuple[Path, str], Lock] = {}
_DATABASE_LOCKS_GUARD = Lock()
_STORE_OPEN_ATTEMPTS = 100
_STORE_OPEN_MAX_DELAY_SECONDS = 0.05
_SESSION_DATABASE_RE = re.compile(r"^session-[0-9a-f]{64}\.sqlite3$")


@dataclass(slots=True)
class _ContinuityRuntime:
    target: Path
    git_directory: Path | None
    state_home: Path
    session_key: str
    clock: Clock
    target_adapter: TargetAdapter
    loaded_policy: LoadedPolicy
    policy_path: Path | None = None
    profile_override: Profile | None = None
    promotion_mode_override: PromotionMode | None = None
    database_name: str | None = None
    instruction_paths: tuple[bytes, ...] | None = None

    @property
    def head_name(self) -> str:
        return f"session:{self.session_key}:checkpoint"


def _session_unavailable() -> Exception:
    from agent_continuity.api import ContinuityRequestError

    return ContinuityRequestError("continuity session is unavailable")


def database_lock(runtime: _ContinuityRuntime, name: str) -> Lock:
    key = (runtime.state_home, name)
    with _DATABASE_LOCKS_GUARD:
        return _DATABASE_LOCKS.setdefault(key, Lock())


@contextmanager
def open_store_with_bounded_reconciliation(
    runtime: _ContinuityRuntime,
    *,
    database_name: str,
    store_id: str,
) -> Iterator[SQLiteStateStore]:
    """Adopt a concurrently created store or fail closed after a fixed bound."""

    for attempt in range(_STORE_OPEN_ATTEMPTS):
        state_root = None
        try:
            state_root = open_external_state_root(
                runtime.target,
                runtime.git_directory,
                runtime.state_home,
            )
            store = SQLiteStateStore(
                state_root,
                database_name=database_name,
                store_id=store_id,
            )
        except (StatePathError, StoreIntegrityError):
            if state_root is not None:
                state_root.close()
            if attempt + 1 == _STORE_OPEN_ATTEMPTS:
                raise
            delay = min(
                0.001 * (attempt + 1),
                _STORE_OPEN_MAX_DELAY_SECONDS,
            )
            time.sleep(delay)
            continue
        try:
            yield store
        finally:
            store.close()
        return
    raise AssertionError("bounded store-open loop did not terminate")


@contextmanager
def open_existing_store(
    runtime: _ContinuityRuntime,
    *,
    database_name: str,
    read_only: bool,
) -> Iterator[SQLiteStateStore]:
    """Open an existing session store without admitting store creation."""

    if not os.path.lexists(runtime.state_home):
        raise _session_unavailable()
    state_root = None
    store = None
    missing = False
    try:
        state_root = open_external_state_root(
            runtime.target,
            runtime.git_directory,
            runtime.state_home,
        )
        store = SQLiteStateStore(
            state_root,
            database_name=database_name,
            store_id=None,
            read_only=read_only,
        )
    except StoreValidationError:
        missing = True
        if state_root is not None:
            state_root.close()
    if missing or store is None:
        raise _session_unavailable()
    try:
        yield store
    finally:
        store.close()


def discover_database_name(runtime: _ContinuityRuntime) -> str:
    if runtime.database_name is not None:
        return runtime.database_name
    if not os.path.lexists(runtime.state_home):
        raise _session_unavailable()
    with open_external_state_root(
        runtime.target,
        runtime.git_directory,
        runtime.state_home,
    ) as state_root:
        candidates = tuple(
            sorted(
                name
                for name in os.listdir(state_root.dir_fd)
                if _SESSION_DATABASE_RE.fullmatch(name) is not None
            )
        )
    matches: list[str] = []
    for database_name in candidates:
        with open_existing_store(
            runtime,
            database_name=database_name,
            read_only=True,
        ) as store:
            if store.read_head(runtime.head_name) is not None:
                matches.append(database_name)
    if not matches:
        raise _session_unavailable()
    if len(matches) != 1:
        raise StoreIntegrityError("continuity session mapping is ambiguous")
    runtime.database_name = matches[0]
    return matches[0]


@contextmanager
def open_session_store(
    runtime: _ContinuityRuntime,
    *,
    read_only: bool = True,
) -> Iterator[SQLiteStateStore]:
    database_name = discover_database_name(runtime)
    missing = False
    with open_existing_store(
        runtime,
        database_name=database_name,
        read_only=read_only,
    ) as store:
        if store.read_head(runtime.head_name) is None:
            missing = True
        else:
            yield store
    if missing:
        raise _session_unavailable()


def load_checkpoint_record(
    store: SQLiteStateStore,
    checkpoint_id: RecordId,
) -> CheckpointV1 | None:
    try:
        record = store.load_record(checkpoint_id)
    except KeyError:
        return None
    invalid = False
    try:
        checkpoint = checkpoint_from_record(record)
    except (CanonicalJSONError, KeyError, TypeError, ValueError):
        invalid = True
    if invalid:
        raise StoreIntegrityError("checkpoint record is invalid")
    return checkpoint


def select_checkpoint(
    store: SQLiteStateStore,
    *,
    head_name: str,
    selector: str,
) -> CheckpointV1 | None:
    head = store.read_head(head_name)
    if head is None:
        return None
    selected_id = head.record_id if selector == "latest" else RecordId(selector)
    current = load_checkpoint_record(store, head.record_id)
    seen: set[RecordId] = set()
    while current is not None:
        if current.checkpoint_id == selected_id:
            return current
        if current.parent_checkpoint_id is None or current.checkpoint_id in seen:
            return None
        seen.add(current.checkpoint_id)
        current = load_checkpoint_record(store, current.parent_checkpoint_id)
    return None


def load_instruction_paths(
    store: SQLiteStateStore,
    instruction_id: RecordId,
) -> tuple[bytes, ...]:
    try:
        record = store.load_record(instruction_id)
    except KeyError:
        record = None
    if record is None:
        raise StoreIntegrityError("instruction record is invalid")
    invalid = False
    try:
        paths = instruction_paths_from_record(record)
    except (CanonicalJSONError, KeyError, TypeError, ValueError):
        invalid = True
    if invalid:
        raise StoreIntegrityError("instruction record is invalid")
    return paths


def capture_matches_checkpoint(
    checkpoint: CheckpointV1,
    snapshot: CaptureSnapshot,
) -> bool:
    return (
        snapshot.target.record().record_id == checkpoint.target_id
        and snapshot.instruction_record().record_id == checkpoint.instruction_id
    )


def _payload_string(payload: Mapping[str, object], field: str) -> str:
    value = payload[field]
    if type(value) is not str:
        raise StoreIntegrityError("stored record field is invalid")
    return value


def _payload_string_tuple(
    payload: Mapping[str, object], field: str
) -> tuple[str, ...]:
    value = payload[field]
    if type(value) is not list:
        raise StoreIntegrityError("stored record field is invalid")
    result: list[str] = []
    for item in value:
        if type(item) is not str:
            raise StoreIntegrityError("stored record field is invalid")
        result.append(item)
    return tuple(result)


def load_initialization_ruleset(
    store: SQLiteStateStore,
    intent_id: RecordId,
) -> InitializationIntentV1:
    """Load and verify the checkpoint-linked Plan 2 ruleset authority."""

    try:
        stored_intent = store.load_record(intent_id)
        if (
            stored_intent.record_type != "InitializationIntent"
            or stored_intent.schema_version != "v1"
        ):
            raise StoreIntegrityError("initialization intent record is invalid")
        payload = canonical_loads(stored_intent.canonical_bytes)
        if set(payload) != {
            "criterion_ids",
            "goal_id",
            "instruction_id",
            "policy_id",
            "ruleset_id",
            "session_key",
            "target_id",
        }:
            raise StoreIntegrityError("initialization intent record is invalid")
        criterion_ids = _payload_string_tuple(payload, "criterion_ids")
        intent = build_initialization_intent(
            session_key=_payload_string(payload, "session_key"),
            target_id=RecordId(_payload_string(payload, "target_id")),
            goal_id=RecordId(_payload_string(payload, "goal_id")),
            criterion_ids=tuple(RecordId(item) for item in criterion_ids),
            instruction_id=RecordId(_payload_string(payload, "instruction_id")),
            policy_id=RecordId(_payload_string(payload, "policy_id")),
            ruleset_id=RecordId(_payload_string(payload, "ruleset_id")),
        )
        if intent.intent_id != intent_id or intent.record() != stored_intent:
            raise StoreIntegrityError("initialization intent record is invalid")

        stored_ruleset = store.load_record(intent.ruleset_id)
        if (
            stored_ruleset.record_type != "Ruleset"
            or stored_ruleset.schema_version != "v1"
        ):
            raise StoreIntegrityError("ruleset record is invalid")
        ruleset_payload = canonical_loads(stored_ruleset.canonical_bytes)
        if set(ruleset_payload) != {"rule_ids"}:
            raise StoreIntegrityError("ruleset record is invalid")
        rule_ids = _payload_string_tuple(ruleset_payload, "rule_ids")
        ruleset = build_ruleset(tuple(RecordId(item) for item in rule_ids))
        if (
            ruleset.ruleset_id != intent.ruleset_id
            or ruleset.record() != stored_ruleset
        ):
            raise StoreIntegrityError("ruleset record is invalid")
        return intent
    except StoreIntegrityError:
        raise
    except (
        KeyError,
        CanonicalJSONError,
        RecordSchemaError,
        TypeError,
        ValueError,
    ) as error:
        raise StoreIntegrityError("initialization intent record is invalid") from error


def load_goal_record(store: SQLiteStateStore, goal_id: RecordId) -> GoalV1:
    """Load one exact same-store Goal/v1 or normalize it to integrity failure."""

    try:
        decoded = decode_record(store.load_record(goal_id))
    except (
        KeyError,
        CanonicalJSONError,
        RecordSchemaError,
        TypeError,
        ValueError,
    ) as error:
        raise StoreIntegrityError("goal record is invalid") from error
    if type(decoded) is not GoalV1 or decoded.goal_id != goal_id:
        raise StoreIntegrityError("goal record is invalid")
    return decoded


def load_actor_producer_ids(
    store: SQLiteStateStore,
    actor_ids: tuple[RecordId, ...],
) -> frozenset[RecordId]:
    """Load independent trusted producer identities from checkpoint Actor/v1."""

    producer_ids: set[RecordId] = set()
    for actor_id in actor_ids:
        try:
            decoded = decode_record(store.load_record(actor_id))
        except (
            KeyError,
            CanonicalJSONError,
            RecordSchemaError,
            TypeError,
            ValueError,
        ) as error:
            raise StoreIntegrityError("actor record is invalid") from error
        if type(decoded) is not ActorV1 or decoded.actor_id != actor_id:
            raise StoreIntegrityError("actor record is invalid")
        producer_ids.add(
            make_record(
                "ProducerIdentity",
                producer_identity_payload(decoded.producer),
            ).record_id
        )
    return frozenset(producer_ids)


def load_evidence_graph(
    store: SQLiteStateStore,
    evidence_ids: tuple[RecordId, ...],
) -> dict[RecordId, EvidenceV1]:
    """Load checkpoint-linked Evidence plus available transitive dependencies."""

    graph: dict[RecordId, EvidenceV1] = {}
    required = list(evidence_ids)
    checkpoint_linked = frozenset(evidence_ids)
    attempted: set[RecordId] = set()
    while required:
        evidence_id = required.pop()
        if evidence_id in attempted:
            continue
        attempted.add(evidence_id)
        try:
            stored = store.load_record(evidence_id)
        except KeyError as error:
            if evidence_id in checkpoint_linked:
                raise StoreIntegrityError("evidence record is invalid") from error
            continue
        try:
            decoded = decode_record(stored)
        except (CanonicalJSONError, RecordSchemaError, TypeError, ValueError) as error:
            raise StoreIntegrityError("evidence record is invalid") from error
        if type(decoded) is not EvidenceV1 or decoded.evidence_id != evidence_id:
            raise StoreIntegrityError("evidence record is invalid")
        graph[evidence_id] = decoded
        required.extend(
            invalidator.subject_id
            for invalidator in decoded.invalidators
            if invalidator.kind is InvalidatorKind.EVIDENCE_DEPENDENCY
            and invalidator.subject_id not in attempted
        )
    return graph


def load_citation_records(
    store: SQLiteStateStore,
    evidence: dict[RecordId, EvidenceV1],
) -> dict[RecordId, CitationV1]:
    """Load every same-store Citation/v1 referenced by the evidence graph."""

    citation_ids = tuple(
        sorted(
            {
                invalidator.subject_id
                for record in evidence.values()
                for invalidator in record.invalidators
                if invalidator.kind is InvalidatorKind.CITATION
            }
        )
    )
    citations: dict[RecordId, CitationV1] = {}
    for citation_id in citation_ids:
        try:
            decoded = decode_record(store.load_record(citation_id))
        except (
            KeyError,
            CanonicalJSONError,
            RecordSchemaError,
            TypeError,
            ValueError,
        ) as error:
            raise StoreIntegrityError("citation record is invalid") from error
        if type(decoded) is not CitationV1 or decoded.record().record_id != citation_id:
            raise StoreIntegrityError("citation record is invalid")
        citations[citation_id] = decoded
    return citations


def checkpoint_lineage_ids(
    store: SQLiteStateStore,
    current: CheckpointV1,
) -> frozenset[RecordId]:
    """Return the verified current checkpoint ancestry from the same connection."""

    lineage: set[RecordId] = set()
    cursor: CheckpointV1 | None = current
    while cursor is not None:
        if cursor.checkpoint_id in lineage:
            raise StoreIntegrityError("checkpoint lineage is invalid")
        lineage.add(cursor.checkpoint_id)
        if cursor.parent_checkpoint_id is None:
            break
        cursor = load_checkpoint_record(store, cursor.parent_checkpoint_id)
        if cursor is None:
            raise StoreIntegrityError("checkpoint lineage is invalid")
    return frozenset(lineage)
