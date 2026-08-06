-- SPDX-License-Identifier: AGPL-3.0-or-later
-- KMS-wrapped exact sources for verifier-admitted production operations.

CREATE TABLE AuthoritySources (
  Environment STRING(32) NOT NULL,
  RecordID STRING(128) NOT NULL,
  ParentID STRING(128) NOT NULL,
  Ordinal INT64 NOT NULL,
  State STRING(64) NOT NULL,
  PayloadJSON STRING(MAX) NOT NULL,
  UpdatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true),
  CONSTRAINT CK_AuthoritySources_Ordinal CHECK (Ordinal >= 0)
) PRIMARY KEY (Environment, RecordID);
