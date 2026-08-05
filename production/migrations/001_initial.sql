-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Phase 16 production authority schema. GoogleSQL dialect.

CREATE TABLE AuthorityHead (
  Environment STRING(32) NOT NULL,
  Revision INT64 NOT NULL,
  NextSequence INT64 NOT NULL,
  TrustedSequence INT64 NOT NULL,
  LastTrustedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  StateJSON STRING(MAX) NOT NULL,
  SchemaVersion STRING(64) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_AuthorityHead_Revision CHECK (Revision >= 0),
  CONSTRAINT CK_AuthorityHead_Sequence CHECK (NextSequence > 0 AND TrustedSequence > 0)
) PRIMARY KEY (Environment);

CREATE TABLE Operations (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_Operations_Ordinal CHECK (Ordinal >= 0)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE Approvals (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_Approvals_Ordinal CHECK (Ordinal > 0)
) PRIMARY KEY (Environment, ParentID, RecordID);

CREATE TABLE Profiles (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE Relays (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE Publications (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_Publications_Version CHECK (Ordinal > 0)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE EmergencyAuthorities (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE EmergencyRestrictions (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_EmergencyRestrictions_Epoch CHECK (Ordinal > 0)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE KeyVersions (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE Ceremonies (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE OutboxEvents (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  LeaseOwner STRING(128),
  LeaseUntil TIMESTAMP,
  FencingToken INT64 NOT NULL DEFAULT (0),
  AttemptCount INT64 NOT NULL DEFAULT (0),
  CONSTRAINT CK_Outbox_Ordinal CHECK (Ordinal > 0),
  CONSTRAINT CK_Outbox_Fence CHECK (FencingToken >= 0 AND AttemptCount >= 0)
) PRIMARY KEY (Environment, RecordID);

CREATE INDEX OutboxByState ON OutboxEvents(Environment, State, Ordinal);

CREATE TABLE AuditEvents (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_Audit_Sequence CHECK (Ordinal > 0)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE AuditAnchors (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_AuditAnchors_Sequence CHECK (Ordinal > 0)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE IdempotencyReceipts (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_Idempotency_Revision CHECK (Ordinal > 0)
) PRIMARY KEY (Environment, RecordID);

CREATE TABLE SchemaMigrations (
  Environment STRING(32) NOT NULL,
  Version INT64 NOT NULL,
  Name STRING(128) NOT NULL,
  SHA256 STRING(64) NOT NULL,
  AppliedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  AppliedByDigest STRING(64) NOT NULL,
  CONSTRAINT CK_SchemaMigrations_Version CHECK (Version > 0)
) PRIMARY KEY (Environment, Version);
