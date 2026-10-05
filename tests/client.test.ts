import { describe, expect, it, vi } from 'vitest';
import { Foil } from '../src/client';
import { FoilApiError, FoilConfigurationError } from '../src/errors';
import type {
  ApiKey,
  ApiErrorEnvelope,
  Event,
  IssuedApiKey,
  Organization,
  ResourceEnvelope,
  ResourceListEnvelope,
  SessionDetail,
  SessionSummary,
  VisitorFingerprintDetail,
  VisitorFingerprintSummary,
} from '../src/types';
import { jsonResponse, loadFixture } from './helpers';

function createFetchMock(
  handler: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> | Response,
) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => handler(input, init));
}

describe('Foil client', () => {
  it('uses the env secret key by default', async () => {
    const original = process.env.FOIL_SECRET_KEY;
    process.env.FOIL_SECRET_KEY = 'sk_env_default';
    const fixture = loadFixture<ResourceListEnvelope<SessionSummary>>('api/sessions/list.json');
    const fetch = createFetchMock(() => jsonResponse(fixture));

    try {
      const client = new Foil({ fetch });
      await client.sessions.list();
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      if (original) process.env.FOIL_SECRET_KEY = original;
      else delete process.env.FOIL_SECRET_KEY;
    }
  });

  it('defers the missing secret key error until a request is made', () => {
    const original = process.env.FOIL_SECRET_KEY;
    delete process.env.FOIL_SECRET_KEY;
    try {
      const client = new Foil({ fetch: createFetchMock(() => jsonResponse({})) });
      expect(client.sessions.list).toBeTypeOf('function');
    } finally {
      if (original) process.env.FOIL_SECRET_KEY = original;
    }
  });

  it('throws at request time when called without a secret key', async () => {
    const original = process.env.FOIL_SECRET_KEY;
    delete process.env.FOIL_SECRET_KEY;
    try {
      const client = new Foil({ fetch: createFetchMock(() => jsonResponse({})) });
      await expect(client.sessions.list()).rejects.toBeInstanceOf(FoilConfigurationError);
    } finally {
      if (original) process.env.FOIL_SECRET_KEY = original;
    }
  });

  it('lists sessions with normalized pagination and auth headers', async () => {
    const fixture = loadFixture<ResourceListEnvelope<SessionSummary>>('api/sessions/list.json');
    const fetch = createFetchMock((input, init) => {
      const url = new URL(String(input));
      expect(url.pathname).toBe('/v1/sessions');
      expect(url.searchParams.get('verdict')).toBe('bot');
      expect(url.searchParams.get('limit')).toBe('25');
      expect(init?.headers).toMatchObject({
        Authorization: 'Bearer sk_live_test',
        'X-Foil-Client': '@abxy/foil-server',
      });
      return jsonResponse(fixture);
    });

    const client = new Foil({ secretKey: 'sk_live_test', fetch });
    const result = await client.sessions.list({ verdict: 'bot', limit: 25 });
    expect(result).toEqual({
      items: fixture.data,
      limit: 50,
      has_more: true,
      next_cursor: 'cur_sessions_page_2',
    });
  });

  it('iterates through paginated session results', async () => {
    const firstPage = loadFixture<ResourceListEnvelope<SessionSummary>>('api/sessions/list.json');
    const secondPage: ResourceListEnvelope<SessionSummary> = {
      data: [
        {
          ...firstPage.data[0],
          id: 'sid_123456789abcdefghjkmnpqrst',
          latest_decision: {
            ...firstPage.data[0].latest_decision,
            event_id: 'evt_3456789abcdefghjkmnpqrstvw',
            evaluated_at: '2026-03-24T20:01:05.000Z',
          },
        },
      ],
      pagination: {
        limit: 50,
        has_more: false,
      },
      meta: {
        request_id: 'req_0123456789abcdef0123456789abcdef',
      },
    };

    const fetch = createFetchMock((input) => {
      const cursor = new URL(String(input)).searchParams.get('cursor');
      return jsonResponse(cursor ? secondPage : firstPage);
    });

    const client = new Foil({ secretKey: 'sk_live_test', fetch });
    const items: SessionSummary[] = [];
    for await (const item of client.sessions.iter({ verdict: 'human' })) {
      items.push(item);
    }

    expect(items.map((item) => item.id)).toEqual(['sid_0123456789abcdefghjkmnpqrs', 'sid_123456789abcdefghjkmnpqrst']);
  });

  it('fetches a session detail resource', async () => {
    const fixture = loadFixture<ResourceEnvelope<SessionDetail>>('api/sessions/detail.json');
    const fetch = createFetchMock((input) => {
      expect(String(input)).toContain('/v1/sessions/sid_0123456789abcdefghjkmnpqrs');
      return jsonResponse(fixture);
    });

    const client = new Foil({ secretKey: 'sk_live_test', fetch });
    const session = await client.sessions.get('sid_0123456789abcdefghjkmnpqrs');
    expect(session).toEqual(fixture.data);
    expect(session.client_user_id).toBe('user_123');
    expect(session.native_runtime_integrity).toBeNull();
    expect(session.native_app).toBeNull();
    expect(session.native_carrier).toBeNull();
    expect(session.native_motion_print).toBeNull();
    expect(session.device_identity).toBeNull();
    expect(session.install_id).toBeNull();
  });

  it('attaches and clears a client user ID on a session', async () => {
    const fixture = loadFixture<ResourceEnvelope<SessionDetail>>('api/sessions/detail.json');
    const fetch = createFetchMock((input, init) => {
      expect(String(input)).toContain('/v1/sessions/sid_0123456789abcdefghjkmnpqrs');
      expect(init?.method).toBe('PATCH');
      expect(init?.headers).toMatchObject({
        Authorization: 'Bearer sk_live_test',
        'Content-Type': 'application/json',
      });
      const body = JSON.parse(String(init?.body));
      expect(['user_123', null]).toContain(body.client_user_id);
      return jsonResponse(fixture);
    });

    const client = new Foil({ secretKey: 'sk_live_test', fetch });
    await expect(client.sessions.attachClientUser('sid_0123456789abcdefghjkmnpqrs', 'user_123')).resolves.toEqual(fixture.data);
    await expect(client.sessions.clearClientUser('sid_0123456789abcdefghjkmnpqrs')).resolves.toEqual(fixture.data);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('lists and fetches fingerprints', async () => {
    const listFixture = loadFixture<ResourceListEnvelope<VisitorFingerprintSummary>>('api/fingerprints/list.json');
    const detailFixture = loadFixture<ResourceEnvelope<VisitorFingerprintDetail>>('api/fingerprints/detail.json');
    const fetch = createFetchMock((input) => {
      const url = String(input);
      if (url.includes('/v1/fingerprints/vid_456789abcdefghjkmnpqrstvwx')) {
        return jsonResponse(detailFixture);
      }
      return jsonResponse(listFixture);
    });

    const client = new Foil({ secretKey: 'sk_live_test', fetch });
    expect(await client.fingerprints.list()).toEqual({
      items: listFixture.data,
      limit: 50,
      has_more: false,
    });
    expect(await client.fingerprints.get('vid_456789abcdefghjkmnpqrstvwx')).toEqual(detailFixture.data);
  });

  it('supports organizations and api key management endpoints', async () => {
    const organizationFixture = loadFixture<ResourceEnvelope<Organization>>('api/organizations/organization.json');
    const organizationCreateFixture = loadFixture<ResourceEnvelope<Organization>>('api/organizations/organization-create.json');
    const organizationUpdateFixture = loadFixture<ResourceEnvelope<Organization>>('api/organizations/organization-update.json');
    const createKeyFixture = loadFixture<ResourceEnvelope<IssuedApiKey>>('api/organizations/api-key-create.json');
    const listKeyFixture = loadFixture<ResourceListEnvelope<ApiKey>>('api/organizations/api-key-list.json');
    const updateKeyFixture = loadFixture<ResourceEnvelope<ApiKey>>('api/organizations/api-key-update.json');
    const revokeKeyFixture = loadFixture<ResourceEnvelope<ApiKey>>('api/organizations/api-key-revoke.json');
    const rotateKeyFixture = loadFixture<ResourceEnvelope<IssuedApiKey>>('api/organizations/api-key-rotate.json');

    const fetch = createFetchMock((input, init) => {
      const url = String(input);
      if (url.endsWith('/api-keys/key_6789abcdefghjkmnpqrstvwxyz/rotations')) {
        return jsonResponse(rotateKeyFixture, { status: 201 });
      }
      if (url.endsWith('/api-keys/key_6789abcdefghjkmnpqrstvwxyz') && init?.method === 'PATCH') {
        return jsonResponse(updateKeyFixture);
      }
      if (url.endsWith('/api-keys/key_6789abcdefghjkmnpqrstvwxyz')) {
        return jsonResponse(revokeKeyFixture);
      }
      if (url.endsWith('/api-keys') && init?.method === 'POST') {
        return jsonResponse(createKeyFixture, { status: 201 });
      }
      if (url.endsWith('/api-keys')) {
        return jsonResponse(listKeyFixture);
      }
      if (url.endsWith('/v1/organizations') && init?.method === 'POST') {
        return jsonResponse(organizationCreateFixture, { status: 201 });
      }
      if (url.endsWith('/v1/organizations/org_56789abcdefghjkmnpqrstvwxy') && init?.method === 'PATCH') {
        return jsonResponse(organizationUpdateFixture);
      }
      return jsonResponse(organizationFixture);
    });

    const client = new Foil({ secretKey: 'sk_live_test', fetch });
    expect(await client.organizations.get('org_56789abcdefghjkmnpqrstvwxy')).toEqual(organizationFixture.data);
    expect(await client.organizations.create({ name: 'Example Organization', slug: 'example-organization' })).toEqual(organizationCreateFixture.data);
    expect(await client.organizations.update('org_56789abcdefghjkmnpqrstvwxy', { name: 'Example Organization' })).toEqual(organizationUpdateFixture.data);
    expect(await client.organizations.apiKeys.create('org_56789abcdefghjkmnpqrstvwxy', { name: 'Production Backend' })).toEqual(createKeyFixture.data);
    expect(await client.organizations.apiKeys.list('org_56789abcdefghjkmnpqrstvwxy')).toEqual({
      items: listKeyFixture.data,
      limit: 50,
      has_more: false,
    });
    expect(
      await client.organizations.apiKeys.update('org_56789abcdefghjkmnpqrstvwxy', 'key_6789abcdefghjkmnpqrstvwxyz', {
        name: 'Updated Web App',
      }),
    ).toEqual(updateKeyFixture.data);
    await expect(client.organizations.apiKeys.revoke('org_56789abcdefghjkmnpqrstvwxy', 'key_6789abcdefghjkmnpqrstvwxyz')).resolves.toEqual(revokeKeyFixture.data);
    expect(await client.organizations.apiKeys.rotate('org_56789abcdefghjkmnpqrstvwxy', 'key_6789abcdefghjkmnpqrstvwxyz')).toEqual(rotateKeyFixture.data);
  });

  it('uses organization event history for webhook deliveries', async () => {
    const delivery = {
      object: 'webhook_delivery',
      id: 'wdlv_0123456789abcdef0123456789abcdef',
      event_id: 'wevt_0123456789abcdef0123456789abcdef',
      endpoint_id: 'we_0123456789abcdef0123456789abcdef',
      event_type: 'session.result.persisted',
      status: 'succeeded',
      attempts: 1,
      response_status: 200,
      response_body: '{}',
      error: null,
      created_at: '2026-03-24T20:00:00.000Z',
      updated_at: '2026-03-24T20:00:05.000Z',
    } as const;
    const event: Event = {
      object: 'event',
      id: 'wevt_0123456789abcdef0123456789abcdef',
      type: 'session.result.persisted',
      subject: { type: 'session', id: 'sid_0123456789abcdefghjkmnpqrs' },
      data: { source: 'waitForFingerprint' },
      webhook_deliveries: [delivery],
      created_at: '2026-03-24T20:00:00.000Z',
    };
    const listResponse: ResourceListEnvelope<Event> = {
      data: [event],
      pagination: { limit: 25, has_more: false },
      meta: { request_id: 'req_0123456789abcdef0123456789abcdef' },
    };
    const detailResponse: ResourceEnvelope<Event> = {
      data: event,
      meta: { request_id: 'req_0123456789abcdef0123456789abcdef' },
    };

    const fetch = createFetchMock((input, init) => {
      const url = new URL(String(input));
      expect(init?.headers).toMatchObject({ Authorization: 'Bearer sk_live_test' });
      if (url.pathname === '/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/events') {
        expect(url.searchParams.get('endpoint_id')).toBe('we_0123456789abcdef0123456789abcdef');
        expect(url.searchParams.get('type')).toBe('session.result.persisted');
        return jsonResponse(listResponse);
      }
      if (url.pathname === '/v1/organizations/org_56789abcdefghjkmnpqrstvwxy/events/wevt_0123456789abcdef0123456789abcdef') {
        return jsonResponse(detailResponse);
      }
      throw new Error(`Unexpected request ${init?.method ?? 'GET'} ${url.pathname}`);
    });

    const client = new Foil({ secretKey: 'sk_live_test', fetch });
    await expect(
      client.webhooks.listEvents('org_56789abcdefghjkmnpqrstvwxy', {
        endpoint_id: 'we_0123456789abcdef0123456789abcdef',
        type: 'session.result.persisted',
        limit: 25,
      }),
    ).resolves.toEqual({
      items: [event],
      limit: 25,
      has_more: false,
    });
    await expect(client.webhooks.retrieveEvent('org_56789abcdefghjkmnpqrstvwxy', 'wevt_0123456789abcdef0123456789abcdef')).resolves.toEqual(event);
  });

  it('parses API errors into FoilApiError', async () => {
    const fixture = loadFixture<ApiErrorEnvelope>('errors/validation-error.json');
    const fetch = createFetchMock(() => jsonResponse(fixture, {
      status: fixture.error.status,
      headers: { 'x-request-id': fixture.error.request_id },
    }));

    const client = new Foil({ secretKey: 'sk_live_test', fetch });

    await expect(client.sessions.list({ limit: 999 })).rejects.toMatchObject({
      name: 'FoilApiError',
      status: 422,
      code: fixture.error.code,
      request_id: fixture.error.request_id,
      field_errors: fixture.error.details?.fields,
      docs_url: fixture.error.docs_url ?? null,
    } satisfies Partial<FoilApiError>);
  });
});
