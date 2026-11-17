// Copyright 2026 Wiva, Inc.
// SPDX-License-Identifier: Apache-2.0
import { expect, test } from 'bun:test';
import { Db } from './db';
import { migrate } from './schema';
import { oidcCallback, provisionIdentity } from './oidc';
import { verifyLogin } from './auth';
import { sha256, type Env } from './util';
import { oidcStart } from './oidc';
import * as client from 'openid-client';
import { OAuth2Server, Events } from 'oauth2-mock-server';

test('callback rejects missing, unbound, expired and replayed transactions', async () => {
  const db = new Db(':memory:');
  migrate(db);
  const env: Env = {
    DB: db,
    OIDC: {
      issuer: 'https://idp.example',
      clientId: 'client',
      clientSecret: 'secret',
      callbackUrl: 'https://app.example/api/oidc/callback',
    },
  };
  const url = new URL('https://app.example/api/oidc/callback?state=state');
  const request = (cookie: string) => new Request(url, { headers: { cookie } });
  try {
    await expect(oidcCallback(env, request(''), url)).rejects.toThrow('Invalid sign-in transaction');
    const insert = db.sqlite.query('INSERT INTO oidc_transactions VALUES (?, ?, ?, ?, ?)');
    insert.run(await sha256('state'), await sha256('browser'), 'verifier', 'nonce', Date.now() + 10000);
    await expect(oidcCallback(env, request('__Host-cr_oidc=other'), url)).rejects.toThrow('Invalid sign-in transaction');
    db.sqlite.query('UPDATE oidc_transactions SET expires_at = 0').run();
    await expect(oidcCallback(env, request('__Host-cr_oidc=browser'), url)).rejects.toThrow('Invalid sign-in transaction');
    db.sqlite.query('UPDATE oidc_transactions SET expires_at = ?').run(Date.now() + 10000);
    // An authorization error consumes the bound transaction before any provider request.
    const errorUrl = new URL(url);
    errorUrl.searchParams.set('error', 'access_denied');
    await expect(oidcCallback(env, request('__Host-cr_oidc=browser'), errorUrl)).rejects.toThrow();
    await expect(oidcCallback(env, request('__Host-cr_oidc=browser'), url)).rejects.toThrow('Invalid sign-in transaction');
  } finally {
    db.sqlite.close();
  }
});

test('OIDC authorization code flow accepts only valid tokens for linked active users', async () => {
  const mock = new OAuth2Server();
  await mock.issuer.keys.generate('RS256');
  await mock.start(0, '127.0.0.1');
  const db = new Db(':memory:');
  migrate(db);
  const issuer = mock.issuer.url!;
  const env: Env = {
    DB: db,
    OIDC: { issuer, clientId: 'client', clientSecret: 'secret', callbackUrl: 'https://app.example/api/oidc/callback' },
  };
  const discover = () =>
    client.discovery(new URL(issuer), 'client', 'secret', undefined, {
      execute: [client.allowInsecureRequests, client.enableNonRepudiationChecks],
    });
  db.sqlite.exec("INSERT INTO users (id, username, pw_hash, pw_salt, created_at) VALUES ('u1', 'alice', 'hash', 'salt', 1)");
  db.sqlite.query('INSERT INTO external_identities VALUES (?, ?, ?, ?)').run(issuer, 'johndoe', 'u1', 1);
  async function attempt(change?: (token: any) => void) {
    const start = await oidcStart(env, discover);
    const cookie = start.headers.get('set-cookie')!.split(';')[0];
    const authorization = await fetch(start.headers.get('location')!, { redirect: 'manual' });
    const url = new URL(authorization.headers.get('location')!);
    if (change) mock.service.on(Events.BeforeTokenSigning, change);
    try {
      return await oidcCallback(env, new Request(url, { headers: { cookie } }), url, discover);
    } finally {
      if (change) mock.service.off(Events.BeforeTokenSigning, change);
    }
  }
  try {
    const success = await attempt();
    expect(success.status).toBe(302);
    expect(success.headers.get('set-cookie')).toContain('__Host-cr_session=');
    expect(db.sqlite.query('SELECT user_id FROM auth_sessions').all()).toEqual([{ user_id: 'u1' }]);
    for (const change of [
      (token: any) => {
        if (token.payload.nonce) token.payload.nonce = 'wrong';
      },
      (token: any) => {
        if (token.payload.nonce) token.payload.aud = 'wrong';
      },
      (token: any) => {
        if (token.payload.nonce) token.payload.iss = 'https://wrong.example';
      },
      (token: any) => {
        if (token.payload.nonce) token.payload.exp = 1;
      },
    ])
      await expect(attempt(change)).rejects.toThrow('OIDC sign-in failed');
    mock.service.once(Events.BeforeResponse, (response) => {
      const jwt = response.body.id_token as string;
      const parts = jwt.split('.');
      parts[2] = (parts[2][0] === 'A' ? 'B' : 'A') + parts[2].slice(1);
      response.body.id_token = parts.join('.');
    });
    await expect(attempt()).rejects.toThrow('OIDC sign-in failed');
    const start = await oidcStart(env, discover);
    const cookie = start.headers.get('set-cookie')!.split(';')[0];
    const auth = await fetch(start.headers.get('location')!, { redirect: 'manual' });
    const callback = new URL(auth.headers.get('location')!);
    db.sqlite.query('UPDATE oidc_transactions SET verifier = ?').run(client.randomPKCECodeVerifier());
    await expect(oidcCallback(env, new Request(callback, { headers: { cookie } }), callback, discover)).rejects.toThrow(
      'OIDC sign-in failed',
    );
    db.sqlite.exec("UPDATE users SET disabled = 1 WHERE id = 'u1'");
    await expect(attempt()).rejects.toThrow('This account is disabled');
    db.sqlite.exec('DELETE FROM external_identities');
    await expect(attempt()).rejects.toThrow();
    expect(db.sqlite.query('SELECT count(*) AS n FROM auth_sessions').get()).toEqual({ n: 1 });
    db.sqlite.exec(
      "INSERT INTO users (id, username, pw_hash, pw_salt, is_admin, created_at) VALUES ('admin', 'admin', 'hash', 'salt', 1, 1)",
    );
    const firstLogin = await attempt((token) => {
      if (token.payload.nonce) {
        token.payload.email = 'newuser@example.com';
        token.payload.email_verified = true;
      }
    });
    expect(firstLogin.status).toBe(302);
    expect(db.sqlite.query("SELECT username, is_admin, password_login FROM users WHERE username = 'newuser'").get()).toEqual({
      username: 'newuser',
      is_admin: 0,
      password_login: 0,
    });
  } finally {
    db.sqlite.close();
    await mock.stop();
  }
});

test('first sign-in provisions an identity atomically and never enables password login', async () => {
  const db = new Db(':memory:');
  migrate(db);
  const env: Env = { DB: db };
  try {
    expect(() => provisionIdentity(env, 'issuer', 'subject', 'alice@example.com')).toThrow('Set up an administrator');
    db.sqlite.exec(
      "INSERT INTO users (id, username, pw_hash, pw_salt, is_admin, created_at) VALUES ('admin', 'admin', 'hash', 'salt', 1, 1)",
    );
    expect(() => provisionIdentity(env, 'issuer', 'subject')).toThrow('verified email');
    expect(() => provisionIdentity(env, 'issuer', 'subject', 'admin@example.com')).toThrow('Username already exists');
    expect(() => provisionIdentity(env, 'issuer', 'subject', 'a@example.com')).toThrow('cannot be used');
    const user = provisionIdentity(env, 'issuer', 'subject', 'Alice@example.com');
    expect(user.username).toBe('alice');
    expect(user.isAdmin).toBe(false);
    expect(provisionIdentity(env, 'issuer', 'subject')).toEqual(user);
    await expect(verifyLogin(env, 'alice', 'anything')).rejects.toThrow('Wrong username or password');
    expect(db.sqlite.query('SELECT count(*) AS n FROM external_identities').get()).toEqual({ n: 1 });
    db.sqlite.query('UPDATE users SET disabled = 1 WHERE id = ?').run(user.id);
    expect(() => provisionIdentity(env, 'issuer', 'subject', 'other@example.com')).toThrow('disabled');
  } finally {
    db.sqlite.close();
  }
});
