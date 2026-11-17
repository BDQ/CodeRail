-- Copyright 2026 Wiva, Inc.
-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE external_identities (
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (issuer, subject)
);
CREATE INDEX external_identities_user ON external_identities(user_id);
