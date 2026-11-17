// Copyright 2026 Wiva, Inc.
// SPDX-License-Identifier: Apache-2.0

export interface OidcConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  callbackUrl: string;
}

/** Optional OIDC configuration. Local login remains available. */
export function readOidcConfig(env: Record<string, string | undefined>): OidcConfig | undefined {
  const keys = ['OIDC_ISSUER', 'OIDC_CLIENT_ID', 'OIDC_CLIENT_SECRET', 'OIDC_CALLBACK_URL'] as const;
  if (keys.every((key) => !env[key])) return undefined;
  const missing = keys.filter((key) => !env[key]?.trim());
  if (missing.length) throw new Error(`OIDC configuration requires: ${missing.join(', ')}`);
  for (const key of ['OIDC_ISSUER', 'OIDC_CALLBACK_URL'] as const) {
    let url: URL;
    try { url = new URL(env[key]!); } catch { throw new Error(`${key} must be a valid HTTPS URL`); }
    if (url.protocol !== 'https:' || url.username || url.password || url.search || url.hash) {
      throw new Error(`${key} must be an HTTPS URL without credentials, query, or fragment`);
    }
  }
  if (new URL(env.OIDC_CALLBACK_URL!).pathname !== '/api/oidc/callback') throw new Error('OIDC_CALLBACK_URL must use /api/oidc/callback');
  return { issuer: env.OIDC_ISSUER!, clientId: env.OIDC_CLIENT_ID!, clientSecret: env.OIDC_CLIENT_SECRET!, callbackUrl: env.OIDC_CALLBACK_URL! };
}
