from __future__ import annotations

import pytest

from agent_continuity.kernel.canonical import CanonicalJSONError, digest_bytes
from agent_continuity.kernel.model import RecordId
from agent_continuity.kernel.paths import (
    PathIdentityV1,
    PathScopeKind,
    PathScopeV1,
    detect_case_collisions,
    path_identity_payload,
)
from agent_continuity.kernel.records import FactV1, ProducerIdentity


def test_non_utf8_posix_path_round_trips_exact_bytes_and_offsets() -> None:
    identity = PathIdentityV1.from_bytes("posix-bytes", b"a\xff/b")

    assert identity.raw_bytes() == b"a\xff/b"
    assert identity.raw_b64 == "Yf8vYg"
    assert identity.segment_offsets == (0, 3)
    assert identity.case_key_b64 is None


@pytest.mark.parametrize(
    "raw",
    [b"/absolute", b"a/../b", b"a\x00b", b"a//b", b"a/", b""],
)
def test_posix_path_rejects_unsafe_or_ambiguous_bytes(raw: bytes) -> None:
    with pytest.raises(CanonicalJSONError):
        PathIdentityV1.from_bytes("posix-bytes", raw)


def test_case_collision_detection_uses_explicit_case_identity() -> None:
    upper = PathIdentityV1.from_bytes(
        "posix-bytes", b"README", case_key=b"readme"
    )
    lower = PathIdentityV1.from_bytes(
        "posix-bytes", b"readme", case_key=b"readme"
    )

    with pytest.raises(CanonicalJSONError, match="case-colliding"):
        detect_case_collisions((upper, lower))


def test_display_text_is_derived_and_excluded_from_path_identity() -> None:
    identity = PathIdentityV1.from_bytes("git-path-bytes", b"bad\xff/name")

    payload = path_identity_payload(identity)

    assert payload == {
        "case_key_b64": None,
        "encoding": "git-path-bytes",
        "raw_b64": "YmFk_y9uYW1l",
        "segment_offsets": [0, 5],
    }
    assert "display" not in payload
    assert identity.display() == "bad\\xff/name"


def test_path_scope_is_exact_or_component_aware_without_globs() -> None:
    root = PathScopeV1(path=None, kind=PathScopeKind.TREE)
    tree = PathScopeV1(
        path=PathIdentityV1.from_bytes("posix-bytes", b"src/pkg"),
        kind=PathScopeKind.TREE,
    )
    file_scope = PathScopeV1(
        path=PathIdentityV1.from_bytes("posix-bytes", b"README.md"),
        kind=PathScopeKind.FILE,
    )

    assert root.contains(PathIdentityV1.from_bytes("posix-bytes", b"any/file"))
    assert tree.contains(PathIdentityV1.from_bytes("posix-bytes", b"src/pkg/x.py"))
    assert not tree.contains(PathIdentityV1.from_bytes("posix-bytes", b"src/pkg2"))
    assert file_scope.contains(
        PathIdentityV1.from_bytes("posix-bytes", b"README.md")
    )
    assert not file_scope.contains(
        PathIdentityV1.from_bytes("posix-bytes", b"README.md/child")
    )


def test_file_scope_requires_path_and_never_interprets_glob_characters() -> None:
    with pytest.raises(CanonicalJSONError):
        PathScopeV1(path=None, kind=PathScopeKind.FILE)
    literal = PathScopeV1(
        path=PathIdentityV1.from_bytes("posix-bytes", b"src/*.py"),
        kind=PathScopeKind.FILE,
    )
    assert literal.contains(
        PathIdentityV1.from_bytes("posix-bytes", b"src/*.py")
    )
    assert not literal.contains(
        PathIdentityV1.from_bytes("posix-bytes", b"src/main.py")
    )


def test_producer_and_fact_records_validate_bounded_public_fields() -> None:
    producer = ProducerIdentity(
        name="acg-git",
        version="1.0",
        digest=digest_bytes(b"adapter"),
    )
    fact = FactV1(field_path=("target", "clean"), value=True)

    assert producer.name == "acg-git"
    assert fact.value is True

    with pytest.raises(CanonicalJSONError):
        ProducerIdentity("bad\nname", "1", digest_bytes(b"adapter"))
    with pytest.raises(CanonicalJSONError):
        FactV1(field_path=(), value=True)
    with pytest.raises(CanonicalJSONError):
        FactV1(field_path=("target",), value="bad\nvalue")


def test_path_identity_record_is_content_addressed_without_display_text() -> None:
    identity = PathIdentityV1.from_bytes("posix-bytes", b"notes/\xff")
    subject = RecordId(
        "sha256:0a8f6fb4545021ad6e4948d86aeb13fe351a19d35e8dfe500b999689754bc67a"
    )

    assert identity.record().record_id != subject
    assert identity.record().canonical_bytes == (
        b'{"case_key_b64":null,"encoding":"posix-bytes",'
        b'"raw_b64":"bm90ZXMv_w","segment_offsets":[0,6]}'
    )
