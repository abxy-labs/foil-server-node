import { createCipheriv, createHash, randomBytes } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { safeVerifyFoilToken, verifyFoilToken } from '../src/sealed-token';
import type { VerifiedFoilToken } from '../src/types';
import { FoilConfigurationError, FoilTokenVerificationError } from '../src/errors';
import { loadFixture } from './helpers';

function sealLegacyToken(json: string, secretKey: string): string {
  const secretHash = createHash('sha256').update(secretKey).digest('hex');
  const key = createHash('sha256').update(`${secretHash}\0sealed-results`).digest();
  const nonce = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, nonce);
  const ciphertext = Buffer.concat([cipher.update(deflateSync(Buffer.from(json, 'utf8'))), cipher.final()]);
  return Buffer.concat([Buffer.from([0x01]), nonce, ciphertext, cipher.getAuthTag()]).toString('base64');
}

describe('sealed token verification', () => {
  it('verifies the shared golden vector with the plaintext secret', () => {
    const fixture = loadFixture<{
      secretKey: string;
      token: string;
      payload: VerifiedFoilToken;
    }>('sealed-token/vector.v1.json');

    expect(verifyFoilToken(fixture.token, fixture.secretKey)).toEqual(fixture.payload);
  });

  it('verifies the shared golden vector with the secret hash', () => {
    const fixture = loadFixture<{
      secretHash: string;
      token: string;
      payload: VerifiedFoilToken;
    }>('sealed-token/vector.v1.json');

    expect(verifyFoilToken(fixture.token, fixture.secretHash)).toEqual(fixture.payload);
  });

  it('verifies the multi-recipient vector with every active secret key', () => {
    const fixture = loadFixture<{
      secretKeys: string[];
      secretHashes: string[];
      token: string;
      payload: VerifiedFoilToken;
    }>('sealed-token/vector.v2.json');

    for (const secret of [...fixture.secretKeys, ...fixture.secretHashes]) {
      expect(verifyFoilToken(fixture.token, secret)).toEqual(fixture.payload);
    }
  });

  it('returns a typed failure result for invalid tokens', () => {
    const fixture = loadFixture<{ token: string }>('sealed-token/invalid.json');
    const result = safeVerifyFoilToken(fixture.token, 'sk_live_fixture_secret');

    expect(result.ok).toBe(false);
    if (!result.ok) {
      expect(result.error).toBeInstanceOf(FoilTokenVerificationError);
    }
  });

  it('accepts a payload just under the decompressed size cap', () => {
    const token = sealLegacyToken(JSON.stringify({ padding: 'a'.repeat(1024 * 1024 - 64) }), 'sk_live_cap_test');

    expect(verifyFoilToken(token, 'sk_live_cap_test')).toHaveProperty('padding');
  });

  it('rejects an authentic token whose payload decompresses past the size cap', () => {
    const token = sealLegacyToken(JSON.stringify({ padding: 'a'.repeat(2 * 1024 * 1024) }), 'sk_live_cap_test');

    expect(() => verifyFoilToken(token, 'sk_live_cap_test')).toThrow(FoilTokenVerificationError);
    expect(() => verifyFoilToken(token, 'sk_live_cap_test')).toThrow('Foil token payload is too large.');
  });

  it('throws a configuration error when no secret key is available', () => {
    const fixture = loadFixture<{ token: string }>('sealed-token/vector.v1.json');
    const original = process.env.FOIL_SECRET_KEY;
    delete process.env.FOIL_SECRET_KEY;

    try {
      expect(() => verifyFoilToken(fixture.token)).toThrow(FoilConfigurationError);
    } finally {
      if (original) process.env.FOIL_SECRET_KEY = original;
    }
  });
});
