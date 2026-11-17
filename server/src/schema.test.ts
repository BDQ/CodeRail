// Copyright 2026 Wiva, Inc.
// SPDX-License-Identifier: Apache-2.0
import { expect, test } from 'bun:test';
import { Db } from './db';
import { migrate } from './schema';
import initial from '../migrations/0001_init.sql' with { type: 'text' };
import auditIndex from '../migrations/0002_audit_at.sql' with { type: 'text' };

test('upgrades existing users and grants and enforces external identity ownership', () => {
  const db = new Db(':memory:');
  try {
    const sql = db.sqlite;
    sql.exec(initial);
    sql.exec(auditIndex);
    sql.exec("CREATE TABLE migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL); INSERT INTO migrations VALUES ('0001_init.sql', 0), ('0002_audit_at.sql', 0)");
    sql.exec("INSERT INTO users (id, username, pw_hash, pw_salt, created_at) VALUES ('u1', 'alice', 'hash', 'salt', 1), ('u2', 'bob', 'hash', 'salt', 1)");
    sql.exec("INSERT INTO machines (id, name, token_hash, owner_id, created_at) VALUES ('m1', 'machine', 'token', 'u1', 1)");
    sql.exec("INSERT INTO grants (machine_id, user_id, role) VALUES ('m1', 'u1', 'viewer')");
    migrate(db);
    migrate(db);
    expect(sql.query('SELECT username FROM users WHERE id = ?').get('u1')).toEqual({ username: 'alice' });
    expect(sql.query('SELECT role FROM grants WHERE user_id = ?').get('u1')).toEqual({ role: 'viewer' });
    sql.exec("INSERT INTO external_identities VALUES ('https://idp.example', 'one', 'u1', 1), ('https://idp.example', 'two', 'u1', 1)");
    expect(() => sql.exec("INSERT INTO external_identities VALUES ('https://idp.example', 'one', 'u2', 1)")).toThrow();
    expect(() => sql.exec("INSERT INTO external_identities VALUES ('https://idp.example', 'three', 'missing', 1)")).toThrow();
    sql.exec("DELETE FROM users WHERE id = 'u1'");
    expect(sql.query('SELECT * FROM external_identities').all()).toEqual([]);
  } finally {
    db.sqlite.close();
  }
});
