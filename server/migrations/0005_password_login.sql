-- Copyright 2026 Wiva, Inc.
-- SPDX-License-Identifier: Apache-2.0
ALTER TABLE users ADD COLUMN password_login INTEGER NOT NULL DEFAULT 1;
