// Copyright 2026 Wiva, Inc.
// SPDX-License-Identifier: Apache-2.0
import * as oidc from 'openid-client';
import { startSession } from './auth';
import { type Env, HttpError, now, parseCookies, randomToken, sha256 } from './util';

const COOKIE = '__Host-cr_oidc';
const LIFETIME = 10 * 60;

export async function provider(env: Env) {
  if (!env.OIDC) throw new HttpError(404, 'OIDC is not configured');
  return oidc.discovery(new URL(env.OIDC.issuer), env.OIDC.clientId, env.OIDC.clientSecret, undefined, { execute: [oidc.enableNonRepudiationChecks] });
}

export async function oidcStart(env: Env, discover = provider): Promise<Response> {
  const config = await discover(env);
  const state = oidc.randomState();
  const nonce = oidc.randomNonce();
  const verifier = oidc.randomPKCECodeVerifier();
  const browser = randomToken(32);
  const url = oidc.buildAuthorizationUrl(config, { redirect_uri: env.OIDC!.callbackUrl, scope: 'openid', state, nonce, code_challenge: await oidc.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' });
  await env.DB.prepare('DELETE FROM oidc_transactions WHERE expires_at <= ?').bind(now()).run();
  await env.DB.prepare('INSERT INTO oidc_transactions VALUES (?, ?, ?, ?, ?)').bind(await sha256(state), await sha256(browser), verifier, nonce, now() + LIFETIME * 1000).run();
  return new Response(null, { status: 302, headers: { location: url.href, 'set-cookie': `${COOKIE}=${browser}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${LIFETIME}`, 'cache-control': 'no-store' } });
}

export async function oidcCallback(env: Env, req: Request, url: URL, discover = provider): Promise<Response> {
  if (!env.OIDC) throw new HttpError(404, 'OIDC is not configured');
  const browser = parseCookies(req)[COOKIE];
  const states = url.searchParams.getAll('state');
  if (!browser || states.length !== 1 || !states[0]) throw new HttpError(401, 'Invalid sign-in transaction');
  const transaction = await env.DB.prepare('DELETE FROM oidc_transactions WHERE state_hash = ? AND browser_hash = ? AND expires_at > ? RETURNING verifier, nonce')
    .bind(await sha256(states[0]), await sha256(browser), now()).first<{ verifier: string; nonce: string }>();
  if (!transaction) throw new HttpError(401, 'Invalid sign-in transaction');
  const callback = new URL(env.OIDC.callbackUrl);
  callback.search = url.search;
  let claims: ReturnType<Awaited<ReturnType<typeof oidc.authorizationCodeGrant>>['claims']>;
  try {
    const tokens = await oidc.authorizationCodeGrant(await discover(env), callback, { pkceCodeVerifier: transaction.verifier, expectedState: states[0], expectedNonce: transaction.nonce, idTokenExpected: true });
    claims = tokens.claims();
  } catch {
    throw new HttpError(401, 'OIDC sign-in failed');
  }
  if (!claims?.iss || !claims.sub) throw new HttpError(401, 'OIDC sign-in failed');
  const user = await env.DB.prepare('SELECT u.id, u.username, u.is_admin FROM external_identities i JOIN users u ON u.id = i.user_id WHERE i.issuer = ? AND i.subject = ? AND u.disabled = 0')
    .bind(claims.iss, claims.sub).first<{ id: string; username: string; is_admin: number }>();
  if (!user) throw new HttpError(403, 'No active account is linked to this identity');
  const headers = new Headers({ location: '/', 'cache-control': 'no-store' });
  headers.append('set-cookie', await startSession(env, { id: user.id, username: user.username, isAdmin: !!user.is_admin }, req));
  headers.append('set-cookie', `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
  return new Response(null, { status: 302, headers });
}
