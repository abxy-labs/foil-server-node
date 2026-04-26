import { describe, expect, it, vi } from 'vitest';
import { Tripwire } from '../src/client';
import { TripwireApiError, TripwireConfigurationError } from '../src/errors';
import type {
  ApiKey,
  IssuedApiKey,
  ApiErrorEnvelope,
  ResourceEnvelope,
  ResourceListEnvelope,
  SessionDetail,
  SessionSummary,
  Team,
  VisitorFingerprintDetail,
  VisitorFingerprintSummary,
} from '../src/types';
import { jsonResponse, loadFixture } from './helpers';

function createFetchMock(
  handler: (input: RequestInfo | URL, init?: RequestInit) => Promise<Response> | Response,
) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => handler(input, init));
}

describe('Tripwire client', () => {
  it('uses the env secret key by default', async () => {
    const original = process.env.TRIPWIRE_SECRET_KEY;
    process.env.TRIPWIRE_SECRET_KEY = 'sk_env_default';
    const fixture = loadFixture<ResourceListEnvelope<SessionSummary>>('api/sessions/list.json');
    const fetch = createFetchMock(() => jsonResponse(fixture));

    try {
      const client = new Tripwire({ fetch });
      await client.sessions.list();
      expect(fetch).toHaveBeenCalledTimes(1);
    } finally {
      if (original) process.env.TRIPWIRE_SECRET_KEY = original;
      else delete process.env.TRIPWIRE_SECRET_KEY;
    }
  });

  it('throws when no secret key is configured', () => {
    const original = process.env.TRIPWIRE_SECRET_KEY;
    delete process.env.TRIPWIRE_SECRET_KEY;
    try {
      const client = new Tripwire({ fetch: createFetchMock(() => jsonResponse({})) });
      expect(client.gate).toBeDefined();
      expect(client.gate.registry).toBeDefined();
      expect(client.gate.registry.list).toBeTypeOf('function');
    } finally {
      if (original) process.env.TRIPWIRE_SECRET_KEY = original;
    }
  });

  it('throws at request time when a secret-auth endpoint is called without a secret key', async () => {
    const original = process.env.TRIPWIRE_SECRET_KEY;
    delete process.env.TRIPWIRE_SECRET_KEY;
    try {
      const client = new Tripwire({ fetch: createFetchMock(() => jsonResponse({})) });
      await expect(client.sessions.list()).rejects.toBeInstanceOf(TripwireConfigurationError);
    } finally {
      if (original) process.env.TRIPWIRE_SECRET_KEY = original;
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
        'X-Tripwire-Client': '@abxy/tripwire-server',
      });
      return jsonResponse(fixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
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

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
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

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    expect(await client.sessions.get('sid_0123456789abcdefghjkmnpqrs')).toEqual(fixture.data);
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

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    expect(await client.fingerprints.list()).toEqual({
      items: listFixture.data,
      limit: 50,
      has_more: false,
    });
    expect(await client.fingerprints.get('vid_456789abcdefghjkmnpqrstvwx')).toEqual(detailFixture.data);
  });

  it('supports teams and api key management endpoints', async () => {
    const teamFixture = loadFixture<ResourceEnvelope<Team>>('api/teams/team.json');
    const createKeyFixture = loadFixture<ResourceEnvelope<IssuedApiKey>>('api/teams/api-key-create.json');
    const listKeyFixture = loadFixture<ResourceListEnvelope<ApiKey>>('api/teams/api-key-list.json');
    const revokeKeyFixture = loadFixture<ResourceEnvelope<ApiKey>>('api/teams/api-key-revoke.json');
    const rotateKeyFixture = loadFixture<ResourceEnvelope<IssuedApiKey>>('api/teams/api-key-rotate.json');

    const fetch = createFetchMock((input, init) => {
      const url = String(input);
      if (url.endsWith('/api-keys/key_6789abcdefghjkmnpqrstvwxyz/rotations')) {
        return jsonResponse(rotateKeyFixture, { status: 201 });
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
      return jsonResponse(teamFixture);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });
    expect(await client.teams.get('team_56789abcdefghjkmnpqrstvwxy')).toEqual(teamFixture.data);
    expect(await client.teams.create({ name: 'Example Team', slug: 'example-team' })).toEqual(teamFixture.data);
    expect(await client.teams.update('team_56789abcdefghjkmnpqrstvwxy', { name: 'Example Team' })).toEqual(teamFixture.data);
    expect(await client.teams.apiKeys.create('team_56789abcdefghjkmnpqrstvwxy', { name: 'Production' })).toEqual(createKeyFixture.data);
    expect(await client.teams.apiKeys.list('team_56789abcdefghjkmnpqrstvwxy')).toEqual({
      items: listKeyFixture.data,
      limit: 50,
      has_more: false,
    });
    await expect(client.teams.apiKeys.revoke('team_56789abcdefghjkmnpqrstvwxy', 'key_6789abcdefghjkmnpqrstvwxyz')).resolves.toEqual(revokeKeyFixture.data);
    expect(await client.teams.apiKeys.rotate('team_56789abcdefghjkmnpqrstvwxy', 'key_6789abcdefghjkmnpqrstvwxyz')).toEqual(rotateKeyFixture.data);
  });

  it('supports the gate namespace across public, bearer, and secret-auth routes', async () => {
    const registryListFixture = loadFixture<ResourceEnvelope<any[]>>('api/gate/registry-list.json');
    const registryDetailFixture = loadFixture<ResourceEnvelope<any>>('api/gate/registry-detail.json');
    const servicesListFixture = loadFixture<ResourceEnvelope<any[]>>('api/gate/services-list.json');
    const serviceDetailFixture = loadFixture<ResourceEnvelope<any>>('api/gate/service-detail.json');
    const serviceCreateFixture = loadFixture<ResourceEnvelope<any>>('api/gate/service-create.json');
    const serviceUpdateFixture = loadFixture<ResourceEnvelope<any>>('api/gate/service-update.json');
    const serviceDisableFixture = loadFixture<ResourceEnvelope<any>>('api/gate/service-disable.json');
    const sessionCreateFixture = loadFixture<ResourceEnvelope<any>>('api/gate/session-create.json');
    const sessionPollFixture = loadFixture<ResourceEnvelope<any>>('api/gate/session-poll.json');
    const sessionAckFixture = loadFixture<ResourceEnvelope<any>>('api/gate/session-ack.json');
    const loginCreateFixture = loadFixture<ResourceEnvelope<any>>('api/gate/login-session-create.json');
    const loginConsumeFixture = loadFixture<ResourceEnvelope<any>>('api/gate/login-session-consume.json');
    const agentVerifyFixture = loadFixture<ResourceEnvelope<any>>('api/gate/agent-token-verify.json');

    const fetch = createFetchMock(async (input, init) => {
      const url = new URL(String(input));
      const headers = new Headers(init?.headers);
      const auth = headers.get('authorization');
      const bodyText = init?.body ? String(init.body) : '';
      const body = bodyText ? JSON.parse(bodyText) as Record<string, unknown> : null;

      if (url.pathname === '/v1/gate/registry' && init?.method !== 'POST') {
        expect(auth).toBeNull();
        return jsonResponse(registryListFixture);
      }
      if (url.pathname === '/v1/gate/registry/tripwire') {
        expect(auth).toBeNull();
        return jsonResponse(registryDetailFixture);
      }
      if (url.pathname === '/v1/gate/services' && (!init?.method || init.method === 'GET')) {
        expect(auth).toBe('Bearer sk_live_test');
        return jsonResponse(servicesListFixture);
      }
      if (url.pathname === '/v1/gate/services/tripwire' && (!init?.method || init.method === 'GET')) {
        expect(auth).toBe('Bearer sk_live_test');
        return jsonResponse(serviceDetailFixture);
      }
      if (url.pathname === '/v1/gate/services' && init?.method === 'POST') {
        expect(auth).toBe('Bearer sk_live_test');
        expect(body?.id).toBe('acme_prod');
        return jsonResponse(serviceCreateFixture, { status: 201 });
      }
      if (url.pathname === '/v1/gate/services/acme_prod' && init?.method === 'PATCH') {
        expect(auth).toBe('Bearer sk_live_test');
        expect(body?.discoverable).toBe(true);
        return jsonResponse(serviceUpdateFixture);
      }
      if (url.pathname === '/v1/gate/services/acme_prod' && init?.method === 'DELETE') {
        expect(auth).toBe('Bearer sk_live_test');
        return jsonResponse(serviceDisableFixture);
      }
      if (url.pathname === '/v1/gate/sessions' && init?.method === 'POST') {
        expect(auth).toBeNull();
        expect(body?.service_id).toBe('tripwire');
        return jsonResponse(sessionCreateFixture, { status: 201 });
      }
      if (url.pathname === '/v1/gate/sessions/gate_0123456789abcdefghjkmnpqrs' && (!init?.method || init.method === 'GET')) {
        expect(auth).toBe('Bearer gtpoll_0123456789abcdefghjkmnpqrs');
        return jsonResponse(sessionPollFixture);
      }
      if (url.pathname === '/v1/gate/sessions/gate_0123456789abcdefghjkmnpqrs/ack') {
        expect(auth).toBe('Bearer gtpoll_0123456789abcdefghjkmnpqrs');
        expect(body).toEqual({ ack_token: 'gtack_0123456789abcdefghjkmnpqrs' });
        return jsonResponse(sessionAckFixture);
      }
      if (url.pathname === '/v1/gate/login-sessions') {
        expect(auth).toBe('Bearer agt_0123456789abcdefghjkmnpqrs');
        expect(body).toEqual({ service_id: 'tripwire' });
        return jsonResponse(loginCreateFixture, { status: 201 });
      }
      if (url.pathname === '/v1/gate/login-sessions/consume') {
        expect(auth).toBe('Bearer sk_live_test');
        expect(body).toEqual({ code: 'gate_code_0123456789abcdefghjkm' });
        return jsonResponse(loginConsumeFixture);
      }
      if (url.pathname === '/v1/gate/agent-tokens/verify') {
        expect(auth).toBe('Bearer sk_live_test');
        return jsonResponse(agentVerifyFixture);
      }
      if (url.pathname === '/v1/gate/agent-tokens/revoke') {
        expect(auth).toBe('Bearer sk_live_test');
        return new Response(null, { status: 204 });
      }

      throw new Error(`Unexpected request ${init?.method ?? 'GET'} ${url.pathname}`);
    });

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });

    expect(await client.gate.registry.list()).toEqual(registryListFixture.data);
    expect(await client.gate.registry.get('tripwire')).toEqual(registryDetailFixture.data);
    expect(await client.gate.services.list()).toEqual(servicesListFixture.data);
    expect(await client.gate.services.get('tripwire')).toEqual(serviceDetailFixture.data);
    expect(await client.gate.services.create({
      id: 'acme_prod',
      name: 'Acme Production',
      description: 'Acme production signup flow',
      website: 'https://acme.example.com',
      webhook_endpoint_id: 'we_0123456789abcdef0123456789abcdef',
    })).toEqual(serviceCreateFixture.data);
    expect(await client.gate.services.update('acme_prod', { discoverable: true })).toEqual(serviceUpdateFixture.data);
    expect(await client.gate.services.disable('acme_prod')).toEqual(serviceDisableFixture.data);
    expect(await client.gate.sessions.create({
      service_id: 'tripwire',
      account_name: 'my-project',
      delivery: {
        version: 1,
        algorithm: 'x25519-hkdf-sha256/aes-256-gcm',
        key_id: 'kid_integrator_0123456789abcdefgh',
        public_key: 'public_key_integrator',
      },
    })).toEqual(sessionCreateFixture.data);
    expect(await client.gate.sessions.poll('gate_0123456789abcdefghjkmnpqrs', {
      pollToken: 'gtpoll_0123456789abcdefghjkmnpqrs',
    })).toEqual(sessionPollFixture.data);
    expect(await client.gate.sessions.acknowledge('gate_0123456789abcdefghjkmnpqrs', {
      pollToken: 'gtpoll_0123456789abcdefghjkmnpqrs',
      ack_token: 'gtack_0123456789abcdefghjkmnpqrs',
    })).toEqual(sessionAckFixture.data);
    expect(await client.gate.loginSessions.create({
      service_id: 'tripwire',
      agentToken: 'agt_0123456789abcdefghjkmnpqrs',
    })).toEqual(loginCreateFixture.data);
    expect(await client.gate.loginSessions.consume({
      code: 'gate_code_0123456789abcdefghjkm',
    })).toEqual(loginConsumeFixture.data);
    expect(await client.gate.agentTokens.verify({
      agent_token: 'agt_0123456789abcdefghjkmnpqrs',
    })).toEqual(agentVerifyFixture.data);
    await expect(client.gate.agentTokens.revoke({
      agent_token: 'agt_0123456789abcdefghjkmnpqrs',
    })).resolves.toBeUndefined();
  });

  it('parses API errors into TripwireApiError', async () => {
    const fixture = loadFixture<ApiErrorEnvelope>('errors/validation-error.json');
    const fetch = createFetchMock(() => jsonResponse(fixture, {
      status: fixture.error.status,
      headers: { 'x-request-id': fixture.error.request_id },
    }));

    const client = new Tripwire({ secretKey: 'sk_live_test', fetch });

    await expect(client.sessions.list({ limit: 999 })).rejects.toMatchObject({
      name: 'TripwireApiError',
      status: 422,
      code: fixture.error.code,
      request_id: fixture.error.request_id,
      field_errors: fixture.error.details?.fields,
      docs_url: fixture.error.docs_url ?? null,
    } satisfies Partial<TripwireApiError>);
  });
});
