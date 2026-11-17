-- Copyright 2026 Wiva, Inc.
-- SPDX-License-Identifier: Apache-2.0
CREATE TABLE oidc_transactions (
  state_hash TEXT PRIMARY KEY,
  browser_hash TEXT NOT NULL,
  verifier TEXT NOT NULL,
  nonce TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);
