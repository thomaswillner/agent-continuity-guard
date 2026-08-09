CREATE TABLE metadata (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
) STRICT;

CREATE TABLE records (
    record_id TEXT PRIMARY KEY,
    record_type TEXT NOT NULL,
    schema_version TEXT NOT NULL,
    canonical_bytes BLOB NOT NULL
) STRICT;

CREATE TABLE sensitive_local_values (
    digest TEXT NOT NULL,
    kind TEXT NOT NULL,
    value BLOB NOT NULL,
    PRIMARY KEY (digest, kind)
) STRICT;

CREATE TABLE audit_events (
    sequence INTEGER PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    previous_event_id TEXT,
    canonical_bytes BLOB NOT NULL,
    FOREIGN KEY (previous_event_id) REFERENCES audit_events(event_id)
) STRICT;

CREATE TABLE heads (
    name TEXT PRIMARY KEY,
    record_id TEXT NOT NULL,
    audit_event_id TEXT NOT NULL,
    audit_sequence INTEGER NOT NULL,
    FOREIGN KEY (record_id) REFERENCES records(record_id),
    FOREIGN KEY (audit_event_id) REFERENCES audit_events(event_id)
) STRICT;

CREATE TRIGGER records_no_update
BEFORE UPDATE ON records
BEGIN
    SELECT RAISE(ABORT, 'records are immutable');
END;

CREATE TRIGGER records_no_delete
BEFORE DELETE ON records
BEGIN
    SELECT RAISE(ABORT, 'records are immutable');
END;

CREATE TRIGGER sensitive_local_values_no_update
BEFORE UPDATE ON sensitive_local_values
BEGIN
    SELECT RAISE(ABORT, 'sensitive local values are immutable');
END;

CREATE TRIGGER sensitive_local_values_no_delete
BEFORE DELETE ON sensitive_local_values
BEGIN
    SELECT RAISE(ABORT, 'sensitive local values are immutable');
END;

CREATE TRIGGER audit_events_no_update
BEFORE UPDATE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;

CREATE TRIGGER audit_events_no_delete
BEFORE DELETE ON audit_events
BEGIN
    SELECT RAISE(ABORT, 'audit events are immutable');
END;
