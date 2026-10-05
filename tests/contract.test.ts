import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it } from 'vitest';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const specPath = path.join(__dirname, '..', 'spec', 'openapi.json');
const spec = JSON.parse(readFileSync(specPath, 'utf8')) as {
  paths: Record<string, Record<string, { operationId?: string; tags?: string[] }>>;
  components: {
    schemas: Record<string, {
      pattern?: string;
      enum?: string[];
      required?: string[];
      properties?: Record<string, unknown>;
      [key: string]: unknown;
    }>;
  };
};

function stripExamples<T>(value: T): T {
  if (Array.isArray(value)) {
    return value.map((item) => stripExamples(item)) as T;
  }
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value)
        .filter(([key]) => key !== 'example')
        .map(([key, item]) => [key, stripExamples(item)]),
    ) as T;
  }
  return value;
}

describe('server SDK contract', () => {
  it('contains only the supported public server paths', () => {
    const paths = Object.keys(spec.paths).sort();
    expect(paths).toEqual([
      '/v1/fingerprints',
      '/v1/fingerprints/{visitorId}',
      '/v1/organizations',
      '/v1/organizations/{organizationId}',
      '/v1/organizations/{organizationId}/api-keys',
      '/v1/organizations/{organizationId}/api-keys/{keyId}',
      '/v1/organizations/{organizationId}/api-keys/{keyId}/rotations',
      '/v1/organizations/{organizationId}/events',
      '/v1/organizations/{organizationId}/events/{eventId}',
      '/v1/organizations/{organizationId}/webhooks/endpoints',
      '/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}',
      '/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}/rotations',
      '/v1/organizations/{organizationId}/webhooks/endpoints/{endpointId}/test',
      '/v1/sessions',
      '/v1/sessions/{sessionId}',
    ]);
  });

  it('excludes collect endpoints from the public SDK contract', () => {
    expect(Object.keys(spec.paths).some((key) => key.startsWith('/v1/collect/'))).toBe(false);
  });

  it('tightens the critical public schema constraints', () => {
    const schemas = spec.components.schemas;

    expect(schemas.SessionId.pattern).toBe('^sid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$');
    expect(schemas.FingerprintId.pattern).toBe('^vid_[0123456789abcdefghjkmnpqrstvwxyz]{26}$');
    expect(schemas.OrganizationId.pattern).toBe('^org_[0123456789abcdefghjkmnpqrstvwxyz]{26}$');
    expect(schemas.ApiKeyId.pattern).toBe('^key_[0123456789abcdefghjkmnpqrstvwxyz]{26}$');

    expect(stripExamples(schemas.SessionSummary.properties?.id)).toEqual({ $ref: '#/components/schemas/SessionId' });
    expect(stripExamples(schemas.SessionSummary.properties?.client_user_id)).toEqual({
      type: ['string', 'null'],
      maxLength: 256,
      description: 'Customer-supplied identifier for the end user associated with this Foil session. Set with PATCH /v1/sessions/{sessionId}.',
    });
    expect(stripExamples(schemas.Organization.properties?.status)).toEqual({ $ref: '#/components/schemas/OrganizationStatus' });
    expect(stripExamples(schemas.ApiKey.properties?.status)).toEqual({ $ref: '#/components/schemas/ApiKeyStatus' });
    expect(schemas.PublicError.properties?.code).toMatchObject({
      'x-foil-known-values-ref': '#/components/schemas/KnownPublicErrorCode',
    });
    expect(schemas.OrganizationStatus.enum).toEqual(['active', 'suspended', 'deleted']);
    expect(schemas.ApiKeyStatus.enum).toEqual(['active', 'rotating', 'revoked']);
    expect(schemas.ApiKey.required).toEqual(
      expect.arrayContaining(['type', 'allowed_origins', 'scopes', 'key_preview', 'last_used_at', 'grace_expires_at']),
    );
    expect(schemas.IssuedApiKey.required).toEqual(expect.arrayContaining(['revealed_key']));
    expect(schemas.SessionDetail.required).toEqual(
      expect.arrayContaining([
        'id',
        'client_user_id',
        'decision',
        'highlights',
        'attribution',
        'web_bot_auth',
        'network',
        'runtime_integrity',
        'visitor_fingerprint',
        'connection_fingerprint',
        'previous_decisions',
        'request',
        'browser',
        'device',
        'analysis_coverage',
        'signals_fired',
        'client_telemetry',
      ]),
    );
    expect(stripExamples(schemas.SessionDetail.properties?.request)).toEqual({ $ref: '#/components/schemas/SessionDetailRequest' });
    expect(stripExamples(schemas.SessionDetail.properties?.client_telemetry)).toEqual({
      $ref: '#/components/schemas/SessionClientTelemetry',
    });
    expect(stripExamples(schemas.SessionDetail.properties?.attribution)).toEqual({
      anyOf: [{ $ref: '#/components/schemas/SessionAttribution' }, { type: 'null' }],
    });
    expect(stripExamples(schemas.SessionDetail.properties?.signals_fired)).toEqual({
      type: 'array',
      items: { $ref: '#/components/schemas/SessionSignalFired' },
    });
    expect(schemas.SessionSignalFired.properties?.signal).toMatchObject({
      type: 'string',
    });
    expect(schemas.ApiKey.required).toEqual(expect.arrayContaining(['allowed_origins', 'rate_limit', 'rotated_at', 'revoked_at']));
    expect(schemas.CollectBatchResponse).toBeUndefined();
  });

  it('records stable operation ids and tags for the public server surface', () => {
    expect(spec.paths['/v1/sessions'].get).toMatchObject({
      operationId: 'listSessions',
      tags: ['Sessions'],
    });
    expect(spec.paths['/v1/sessions/{sessionId}'].patch).toMatchObject({
      operationId: 'updateSession',
      tags: ['Sessions'],
    });
    expect(spec.paths['/v1/fingerprints/{visitorId}'].get).toMatchObject({
      operationId: 'getVisitorFingerprint',
      tags: ['Visitor fingerprints'],
    });
    expect(spec.paths['/v1/organizations/{organizationId}'].patch).toMatchObject({
      operationId: 'updateOrganization',
      tags: ['Organizations'],
    });
    expect(spec.paths['/v1/organizations/{organizationId}/api-keys/{keyId}'].patch).toMatchObject({
      operationId: 'updateOrganizationApiKey',
      tags: ['API Keys'],
    });
    expect(spec.paths['/v1/organizations/{organizationId}/api-keys/{keyId}/rotations'].post).toMatchObject({
      operationId: 'rotateOrganizationApiKey',
      tags: ['API Keys'],
    });
  });
});
