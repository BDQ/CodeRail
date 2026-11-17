// Copyright 2026 Wiva, Inc.
// SPDX-License-Identifier: Apache-2.0
import { describe, expect, test } from 'bun:test';
import { readOidcConfig } from './oidc-config';

const valid = { OIDC_ISSUER: 'https://example.okta.com', OIDC_CLIENT_ID: 'client', OIDC_CLIENT_SECRET: 'secret', OIDC_CALLBACK_URL: 'https://coderail.example/api/oidc/callback' };

describe('OIDC configuration', () => {
  test('is optional', () => expect(readOidcConfig({})).toBeUndefined());
  test('accepts complete configuration', () => expect(readOidcConfig(valid)).toEqual({ issuer: valid.OIDC_ISSUER, clientId: 'client', clientSecret: 'secret', callbackUrl: valid.OIDC_CALLBACK_URL }));
  test('rejects partial and empty configuration', () => {
    expect(() => readOidcConfig({ OIDC_CLIENT_ID: 'client' })).toThrow('OIDC_ISSUER');
    expect(() => readOidcConfig({ ...valid, OIDC_CLIENT_SECRET: ' ' })).toThrow('OIDC_CLIENT_SECRET');
  });
  test('rejects unsafe URLs without exposing their contents', () => {
    for (const url of ['http://example.com', 'https://user:secret@example.com', 'https://example.com/?token=secret', 'invalid']) {
      expect(() => readOidcConfig({ ...valid, OIDC_ISSUER: url })).toThrow('OIDC_ISSUER');
      expect(() => readOidcConfig({ ...valid, OIDC_CALLBACK_URL: url })).toThrow('OIDC_CALLBACK_URL');
    }
  });
});
