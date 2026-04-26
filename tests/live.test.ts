import { describe, expect, it } from 'vitest';
import { Tripwire } from '../src/client';
import { TripwireApiError } from '../src/errors';
import type { ApiKey, UpdateOrganizationRequest, VerifiedTripwireToken } from '../src/types';
import { safeVerifyTripwireToken } from '../src/sealed-token';
import { loadFixture } from './helpers';

const describeLive = process.env.TRIPWIRE_LIVE_SMOKE === '1' ? describe : describe.skip;

function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value) {
    throw new Error(`${name} is required for the live smoke suite.`);
  }
  return value;
}

async function findApiKey(client: Tripwire, organizationId: string, keyId: string): Promise<ApiKey | null> {
  let cursor: string | undefined;
  for (;;) {
    const page = await client.organizations.apiKeys.list(organizationId, { limit: 100, ...(cursor ? { cursor } : {}) });
    const found = page.items.find((item) => item.id === keyId);
    if (found) return found;
    if (!page.has_more || !page.next_cursor) return null;
    cursor = page.next_cursor;
  }
}

async function bestEffortRevoke(client: Tripwire, organizationId: string, keyId: string | undefined) {
  if (!keyId) return;
  try {
    await client.organizations.apiKeys.revoke(organizationId, keyId);
  } catch (error) {
    if (error instanceof TripwireApiError && (error.status === 404 || error.code === 'request.not_found')) {
      return;
    }
    throw error;
  }
}

function toUpdateStatus(status: string): UpdateOrganizationRequest['status'] | undefined {
  switch (status) {
    case 'active':
    case 'suspended':
    case 'deleted':
      return status;
    default:
      return undefined;
  }
}

describeLive('live API smoke', () => {
  it('exercises the public server surface', async () => {
    const client = new Tripwire({
      secretKey: requireEnv('TRIPWIRE_SMOKE_SECRET_KEY'),
      baseUrl: process.env.TRIPWIRE_SMOKE_BASE_URL || 'https://api.tripwirejs.com',
    });
    const organizationId = requireEnv('TRIPWIRE_SMOKE_ORGANIZATION_ID');

    let createdKeyId: string | undefined;
    let rotatedKeyId: string | undefined;

    try {
      const sessions = await client.sessions.list({ limit: 1 });
      expect(sessions.items.length).toBeGreaterThan(0);
      if (!sessions.items[0]) {
        throw new Error('Smoke organization must have at least one session for the live smoke suite.');
      }
      const session = await client.sessions.get(sessions.items[0].id);
      expect(session.id).toBe(sessions.items[0].id);

      const fingerprints = await client.fingerprints.list({ limit: 1 });
      expect(fingerprints.items.length).toBeGreaterThan(0);
      if (!fingerprints.items[0]) {
        throw new Error('Smoke organization must have at least one fingerprint for the live smoke suite.');
      }
      const fingerprint = await client.fingerprints.get(fingerprints.items[0].id);
      expect(fingerprint.id).toBe(fingerprints.items[0].id);

      const organization = await client.organizations.get(organizationId);
      expect(organization.id).toBe(organizationId);
      const updatedOrganization = await client.organizations.update(organizationId, {
        name: organization.name,
        ...(toUpdateStatus(organization.status) ? { status: toUpdateStatus(organization.status) } : {}),
      });
      expect(updatedOrganization.name).toBe(organization.name);
      if (toUpdateStatus(organization.status)) {
        expect(updatedOrganization.status).toBe(organization.status);
      }

      const created = await client.organizations.apiKeys.create(organizationId, {
        name: `sdk-smoke-${Date.now().toString(36)}`,
        environment: 'test',
      });
      createdKeyId = created.id;
      expect(created.revealed_key.startsWith('sk_')).toBe(true);

      const listedCreatedKey = await findApiKey(client, organizationId, created.id);
      expect(listedCreatedKey?.id).toBe(created.id);

      const rotated = await client.organizations.apiKeys.rotate(organizationId, created.id);
      rotatedKeyId = rotated.id;
      expect(rotated.revealed_key.startsWith('sk_')).toBe(true);

      const fixture = loadFixture<{
        secretKey: string;
        payload: VerifiedTripwireToken;
        token: string;
      }>('sealed-token/vector.v1.json');
      const verified = safeVerifyTripwireToken(fixture.token, fixture.secretKey);
      expect(verified.ok).toBe(true);
      if (verified.ok) {
        expect(verified.data.session_id).toBe(fixture.payload.session_id);
        expect(verified.data.decision.event_id).toBe(fixture.payload.decision.event_id);
      }
    } finally {
      await bestEffortRevoke(client, organizationId, rotatedKeyId);
      if (createdKeyId !== rotatedKeyId) {
        await bestEffortRevoke(client, organizationId, createdKeyId);
      }
    }
  }, 60_000);
});
