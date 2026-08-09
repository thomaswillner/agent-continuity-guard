from __future__ import annotations

import pytest

import agent_continuity.kernel.paths as paths_module
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


class _StringSubclass(str):
    pass


class _IntegerSubclass(int):
    pass


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


@pytest.mark.parametrize("kind", ["file", "tree", "bogus", object()])
def test_path_scope_rejects_non_enum_runtime_kind(kind: object) -> None:
    path = PathIdentityV1.from_bytes("posix-bytes", b"allowed")

    with pytest.raises(CanonicalJSONError):
        PathScopeV1(path=path, kind=kind)  # type: ignore[arg-type]


def test_path_scope_rejects_non_identity_runtime_path() -> None:
    with pytest.raises(CanonicalJSONError):
        PathScopeV1(path=object(), kind=PathScopeKind.TREE)  # type: ignore[arg-type]


def test_external_path_scope_kind_parser_is_explicit_and_strict() -> None:
    parser = getattr(paths_module, "parse_path_scope_kind", None)
    assert callable(parser)
    assert parser("file") is PathScopeKind.FILE
    assert parser("tree") is PathScopeKind.TREE
    with pytest.raises(CanonicalJSONError):
        parser("bogus")


@pytest.mark.parametrize(
    ("field_path", "value"),
    [
        (["target"], True),
        ((_StringSubclass("target"),), True),
        (("target",), []),
        (("target",), {}),
        (("target",), 1.5),
        (("target",), b"bytes"),
        (("target",), _IntegerSubclass(1)),
    ],
)
def test_fact_rejects_non_tuple_path_or_non_scalar_exact_runtime_types(
    field_path: object,
    value: object,
) -> None:
    with pytest.raises(CanonicalJSONError):
        FactV1(field_path=field_path, value=value)  # type: ignore[arg-type]


def test_case_key_is_trusted_derivation_and_mixed_domains_fail_closed() -> None:
    upper = PathIdentityV1.from_bytes(
        "posix-bytes", b"ALLOWED", case_key=b"allowed"
    )
    lower = PathIdentityV1.from_bytes(
        "posix-bytes", b"allowed", case_key=b"allowed"
    )
    raw_lower = PathIdentityV1.from_bytes("posix-bytes", b"allowed")

    assert PathScopeV1(upper, PathScopeKind.FILE).contains(lower)
    assert not PathScopeV1(upper, PathScopeKind.FILE).contains(raw_lower)
    assert not PathScopeV1(raw_lower, PathScopeKind.FILE).contains(lower)

    with pytest.raises(CanonicalJSONError):
        PathIdentityV1.from_bytes(
            "posix-bytes", b"secret", case_key=b"allowed"
        )


def test_direct_path_identity_constructor_rejects_forged_case_key() -> None:
    secret = PathIdentityV1.from_bytes("posix-bytes", b"secret")
    allowed = PathIdentityV1.from_bytes("posix-bytes", b"allowed")

    with pytest.raises(CanonicalJSONError):
        PathIdentityV1(
            encoding="posix-bytes",
            raw_b64=secret.raw_b64,
            segment_offsets=secret.segment_offsets,
            case_key_b64=allowed.raw_b64,
        )


@pytest.mark.parametrize(
    ("text", "offsets"),
    [
        ("a/b", (0, 4)),
        ("\U0001f600/x", (0, 6)),
        ("src\\nested/file", (0, 8, 22)),
    ],
)
def test_windows_segment_offsets_are_exact_utf16le_byte_offsets(
    text: str,
    offsets: tuple[int, ...],
) -> None:
    identity = PathIdentityV1.from_bytes("windows-utf16le", text.encode("utf-16le"))
    assert identity.segment_offsets == offsets


@pytest.mark.parametrize("text", ["src//file", "src\\/file", "src//"])
def test_windows_repeated_or_mixed_empty_segments_are_rejected(text: str) -> None:
    with pytest.raises(CanonicalJSONError):
        PathIdentityV1.from_bytes("windows-utf16le", text.encode("utf-16le"))


def test_windows_scope_containment_uses_components_across_separator_styles() -> None:
    scope_path = PathIdentityV1.from_bytes(
        "windows-utf16le", "src".encode("utf-16le")
    )
    tree = PathScopeV1(scope_path, PathScopeKind.TREE)

    for text in ("src/file", "src\\file", "src\\nested/file"):
        candidate = PathIdentityV1.from_bytes(
            "windows-utf16le", text.encode("utf-16le")
        )
        assert tree.contains(candidate)

    sibling = PathIdentityV1.from_bytes(
        "windows-utf16le", "src2/file".encode("utf-16le")
    )
    assert not tree.contains(sibling)

    slash_file = PathScopeV1(
        PathIdentityV1.from_bytes(
            "windows-utf16le", "src/file".encode("utf-16le")
        ),
        PathScopeKind.FILE,
    )
    backslash_file = PathIdentityV1.from_bytes(
        "windows-utf16le", "src\\file".encode("utf-16le")
    )
    assert slash_file.contains(backslash_file)
