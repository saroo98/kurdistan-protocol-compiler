-- SPDX-License-Identifier: AGPL-3.0-or-later
-- Durable cross-instance replay protection for privileged operator tokens.

CREATE TABLE TokenReplay (
  Environment STRING(32) NOT NULL,
  ActorID STRING(128) NOT NULL,
  TokenDigest STRING(64) NOT NULL,
  ExpiresAt TIMESTAMP NOT NULL,
  CreatedAt TIMESTAMP NOT NULL OPTIONS (allow_commit_timestamp=true)
) PRIMARY KEY (Environment, ActorID, TokenDigest);

CREATE INDEX TokenReplayByExpiry ON TokenReplay(Environment, ExpiresAt);
