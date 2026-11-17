// Copyright 2026 Wiva, Inc.
// SPDX-License-Identifier: Apache-2.0
import * as oidc from 'openid-client';
import { startSession, type User } from './auth';
import { type Env, HttpError, now, parseCookies, randomId, randomToken, sha256 } from './util';

const COOKIE = '__Host-cr_oidc';
const LIFETIME = 10 * 60;

export async function provider(env: Env) {
  if (!env.OIDC) throw new HttpError(404, 'OIDC is not configured');
  return oidc.discovery(new URL(env.OIDC.issuer), env.OIDC.clientId, env.OIDC.clientSecret, undefined, {
    execute: [oidc.enableNonRepudiationChecks],
  });
}

export async function oidcStart(env: Env, discover = provider): Promise<Response> {
  const config = await discover(env);
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const verifier = oidc.randomPKCECodeVerifier();
  const browser = randomToken(32);
  const url = oidc.buildAuthorizationUrl(config, {
    redirect_uri: env.OIDC!.callbackUrl,
    scope: 'openid email',
    state,
    nonce,
    code_challenge: await oidc.calculatePKCECodeChallenge(verifier),
    code_challenge_method: 'S256',
  });
  await env.DB.prepare('DELETE FROM oidc_transactions WHERE expires_at <= ?').bind(now()).run();
  await env.DB.prepare('INSERT INTO oidc_transactions VALUES (?, ?, ?, ?, ?)')
    .bind(await sha256(state), await sha256(browser), verifier, nonce, now() + LIFETIME * 1000)
    .run();
  return new Response(null, {
    status: 302,
    headers: {
      location: url.href,
      'set-cookie': `${COOKIE}=${browser}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${LIFETIME}`,
      'cache-control': 'no-store',
    },
  });
}

export async function oidcCallback(env: Env, req: Request, url: URL, discover = provider): Promise<Response> {
  if (!env.OIDC) throw new HttpError(404, 'OIDC is not configured');
  const browser = parseCookies(req)[COOKIE];
  const states = url.searchParams.getAll('state');
  if (!browser || states.length !== 1 || !states[0]) throw new HttpError(401, 'Invalid sign-in transaction');
  const transaction = await env.DB.prepare(
    'DELETE FROM oidc_transactions WHERE state_hash = ? AND browser_hash = ? AND expires_at > ? RETURNING verifier, nonce',
  )
    .bind(await sha256(states[0]), await sha256(browser), now())
    .first<{ verifier: string; nonce: string }>();
  if (!transaction) throw new HttpError(401, 'Invalid sign-in transaction');
  const callback = new URL(env.OIDC.callbackUrl);
  callback.search = url.search;
  let claims: ReturnType<Awaited<ReturnType<typeof oidc.authorizationCodeGrant>>['claims']>;
  let email: string | undefined;
  try {
    const config = await discover(env);
    const tokens = await oidc.authorizationCodeGrant(config, callback, {
      pkceCodeVerifier: transaction.verifier,
      expectedState: states[0],
      expectedNonce: transaction.nonce,
      idTokenExpected: true,
    });
    claims = tokens.claims();
    if (claims?.email_verified === true && typeof claims.email === 'string') email = claims.email;
    else if (
      claims?.sub &&
      claims.iss &&
      !env.DB.sqlite.query('SELECT 1 FROM external_identities WHERE issuer = ? AND subject = ?').get(claims.iss, claims.sub)
    ) {
      const info = await oidc.fetchUserInfo(config, tokens.access_token, claims.sub);
      if (info.email_verified === true && typeof info.email === 'string') email = info.email;
    }
  } catch {
    throw new HttpError(401, 'OIDC sign-in failed');
  }
  if (!claims?.iss || !claims.sub) throw new HttpError(401, 'OIDC sign-in failed');
  const user = provisionIdentity(env, claims.iss, claims.sub, email);
  const headers = new Headers({ location: '/', 'cache-control': 'no-store' });
  headers.append('set-cookie', await startSession(env, user, req));
  headers.append('set-cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  return new Response(null, { status: 302, headers });
}

export function provisionIdentity(env: Env, issuer: string, subject: string, email?: string): User {
  return env.DB.sqlite.transaction(() => {
    const db = env.DB.sqlite;
    const linked = db
      .query<
        { id: string; username: string; is_admin: number; disabled: number },
        [string, string]
      >('SELECT u.id, u.username, u.is_admin, u.disabled FROM external_identities i JOIN users u ON u.id = i.user_id WHERE i.issuer = ? AND i.subject = ?')
      .get(issuer, subject);
    if (linked) {
      if (linked.disabled) throw new HttpError(403, 'This account is disabled');
      return { id: linked.id, username: linked.username, isAdmin: !!linked.is_admin };
    }
    if (!db.query('SELECT 1 FROM users WHERE is_admin = 1 AND disabled = 0').get())
      throw new HttpError(403, 'Set up an administrator before OIDC sign-in');
    if (!email || !/^[^@\s]+@[^@\s]+$/.test(email)) throw new HttpError(403, 'A verified email address is required');
    const username = email.split('@')[0].toLowerCase();
    if (!/^[a-z0-9_.-]{2,32}$/.test(username))
      throw new HttpError(409, 'Email cannot be used as a CodeRail username; contact an administrator');
    if (db.query('SELECT 1 FROM users WHERE username = ?').get(username)) {
      throw new HttpError(
        409,
        'Username already exists. Ask an administrator to review machine ownership and grants before deleting the conflicting account',
      );
    }
    const id = randomId();
    const time = now();
    db.query('INSERT INTO users (id, username, pw_hash, pw_salt, is_admin, created_at, password_login) VALUES (?, ?, ?, ?, 0, ?, 0)').run(
      id,
      username,
      '',
      '',
      time,
    );
    db.query('INSERT INTO external_identities (issuer, subject, user_id, created_at) VALUES (?, ?, ?, ?)').run(issuer, subject, id, time);
    return { id, username, isAdmin: false };
  })();
}
