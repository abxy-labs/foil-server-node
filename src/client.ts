import { TripwireApiError, TripwireConfigurationError } from './errors';
import type {
  AcknowledgeGateSessionDeliveryRequest,
  ApiKey,
  ApiKeyListParams,
  AgentTokenVerification,
  ConsumeGateLoginSessionRequest,
  CreateApiKeyRequest,
  CreateGateLoginSessionRequest,
  CreateGateServiceRequest,
  CreateGateSessionRequest,
  CreateOrganizationRequest,
  CreateWebhookEndpointRequest,
  Event,
  EventListParams,
  FingerprintListParams,
  GateDashboardLogin,
  GateLoginSession,
  GateManagedService,
  GateRegistryEntry,
  GateSessionCreate,
  GateSessionDeliveryAcknowledgement,
  GateSessionPollData,
  IssuedApiKey,
  ListResult,
  ApiErrorEnvelope,
  Organization,
  PollGateSessionOptions,
  RevokeGateAgentTokenRequest,
  RequestOptions,
  ResourceEnvelope,
  ResourceListEnvelope,
  SessionDetail,
  SessionListParams,
  SessionSummary,
  TripwireOptions,
  UpdateGateServiceRequest,
  UpdateApiKeyRequest,
  UpdateOrganizationRequest,
  UpdateWebhookEndpointRequest,
  VerifyGateAgentTokenRequest,
  VisitorFingerprintDetail,
  VisitorFingerprintSummary,
  WebhookEndpoint,
  WebhookTest,
} from './types';

const DEFAULT_BASE_URL = 'https://api.tripwirejs.com';
const DEFAULT_TIMEOUT_MS = 30_000;
const SDK_CLIENT_HEADER = '@abxy/tripwire-server';

type QueryValue = string | number | boolean | undefined | null;

interface RequestConfig {
  path: string;
  method?: 'GET' | 'POST' | 'PATCH' | 'DELETE';
  query?: Record<string, QueryValue>;
  body?: unknown;
  signal?: AbortSignal;
  auth?: AuthConfig;
}

interface ResolvedOptions {
  secretKey?: string;
  baseUrl: string;
  timeoutMs: number;
  fetch: typeof globalThis.fetch;
  userAgent?: string;
}

type AuthConfig =
  | { kind?: 'secret' }
  | { kind: 'none' }
  | { kind: 'bearer'; token: string };

function resolveOptions(options: TripwireOptions = {}): ResolvedOptions {
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== 'function') {
    throw new TripwireConfigurationError(
      'Missing fetch implementation. Pass fetch explicitly or use Node 18+.',
    );
  }

  return {
    secretKey: options.secretKey ?? process.env.TRIPWIRE_SECRET_KEY,
    baseUrl: options.baseUrl && options.baseUrl !== '' ? options.baseUrl : DEFAULT_BASE_URL,
    timeoutMs: options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    fetch: fetchImpl,
    userAgent: options.userAgent,
  };
}

function buildUrl(baseUrl: string, path: string, query?: Record<string, QueryValue>): URL {
  const url = new URL(path, baseUrl);
  if (query) {
    for (const [key, value] of Object.entries(query)) {
      if (value === undefined || value === null || value === '') continue;
      url.searchParams.set(key, String(value));
    }
  }
  return url;
}

function createAbortSignal(timeoutMs: number, signal?: AbortSignal) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => {
    controller.abort(new Error(`Tripwire request timed out after ${timeoutMs}ms.`));
  }, timeoutMs);

  const onAbort = () => controller.abort(signal?.reason);
  if (signal) {
    if (signal.aborted) {
      onAbort();
    } else {
      signal.addEventListener('abort', onAbort, { once: true });
    }
  }

  return {
    signal: controller.signal,
    cleanup: () => {
      clearTimeout(timeoutId);
      if (signal) {
        signal.removeEventListener('abort', onAbort);
      }
    },
  };
}

function isApiErrorEnvelope(value: unknown): value is ApiErrorEnvelope {
  return typeof value === 'object'
    && value !== null
    && 'error' in value
    && typeof (value as { error?: unknown }).error === 'object'
    && (value as { error?: unknown }).error !== null;
}

function normalizeListEnvelope<T>(envelope: ResourceListEnvelope<T>): ListResult<T> {
  return {
    items: envelope.data,
    limit: envelope.pagination.limit,
    has_more: envelope.pagination.has_more,
    ...(envelope.pagination.next_cursor ? { next_cursor: envelope.pagination.next_cursor } : {}),
  };
}

function missingSecretKeyError(): TripwireConfigurationError {
  return new TripwireConfigurationError(
    'Missing Tripwire secret key. Pass secretKey explicitly or set TRIPWIRE_SECRET_KEY.',
  );
}

class HttpClient {
  constructor(private readonly options: ResolvedOptions) {}

  async request<T>(config: RequestConfig): Promise<T> {
    const { signal, cleanup } = createAbortSignal(this.options.timeoutMs, config.signal);
    try {
      const response = await this.options.fetch(buildUrl(this.options.baseUrl, config.path, config.query), {
        method: config.method ?? 'GET',
        headers: this.buildHeaders(config),
        ...(config.body !== undefined ? { body: JSON.stringify(config.body) } : {}),
        signal,
      });

      const text = await response.text();
      const payload = text ? JSON.parse(text) as unknown : null;

      if (!response.ok) {
        const requestId = response.headers.get('x-request-id');
        if (isApiErrorEnvelope(payload)) {
          throw new TripwireApiError({
            status: response.status,
            code: payload.error.code,
            message: payload.error.message,
            request_id: requestId ?? payload.error.request_id ?? null,
            field_errors: payload.error.details?.fields ?? [],
            docs_url: payload.error.docs_url ?? null,
            body: payload,
          });
        }

        throw new TripwireApiError({
          status: response.status,
          code: 'request.failed',
          message: response.statusText || 'Tripwire request failed.',
          request_id: requestId,
          body: payload,
        });
      }

      return payload as T;
    } catch (error) {
      if (error instanceof TripwireApiError) {
        throw error;
      }
      if (error instanceof SyntaxError) {
        throw new TripwireApiError({
          status: 500,
          code: 'response.invalid_json',
          message: 'Tripwire API returned invalid JSON.',
          body: undefined,
        });
      }
      throw error;
    } finally {
      cleanup();
    }
  }

  private buildHeaders(config: RequestConfig): Record<string, string> {
    const headers: Record<string, string> = {
      Accept: 'application/json',
      'X-Tripwire-Client': SDK_CLIENT_HEADER,
      ...(this.options.userAgent ? { 'User-Agent': this.options.userAgent } : {}),
      ...(config.body !== undefined ? { 'Content-Type': 'application/json' } : {}),
    };

    const auth = config.auth ?? { kind: 'secret' as const };
    if (auth.kind === 'none') {
      return headers;
    }

    if (auth.kind === 'bearer') {
      if (!auth.token) {
        throw new TripwireConfigurationError('Missing bearer token for this Tripwire request.');
      }
      headers.Authorization = `Bearer ${auth.token}`;
      return headers;
    }

    if (!this.options.secretKey) {
      throw missingSecretKeyError();
    }
    headers.Authorization = `Bearer ${this.options.secretKey}`;
    return headers;
  }
}

async function* iterateCursor<T, TParams extends { cursor?: string } & RequestOptions>(
  list: (params: TParams) => Promise<ListResult<T>>,
  params: Omit<TParams, 'cursor'>,
): AsyncGenerator<T, void, void> {
  let cursor: string | undefined;
  for (;;) {
    const page = await list({ ...params, ...(cursor ? { cursor } : {}) } as TParams);
    for (const item of page.items) {
      yield item;
    }
    if (!page.has_more || !page.next_cursor) {
      return;
    }
    cursor = page.next_cursor;
  }
}

export class Tripwire {
  private readonly http: HttpClient;

  readonly sessions: {
    list: (params?: SessionListParams) => Promise<ListResult<SessionSummary>>;
    get: (sessionId: string, options?: RequestOptions) => Promise<SessionDetail>;
    iter: (params?: Omit<SessionListParams, 'cursor'>) => AsyncGenerator<SessionSummary, void, void>;
  };

  readonly fingerprints: {
    list: (params?: FingerprintListParams) => Promise<ListResult<VisitorFingerprintSummary>>;
    get: (visitorId: string, options?: RequestOptions) => Promise<VisitorFingerprintDetail>;
    iter: (params?: Omit<FingerprintListParams, 'cursor'>) => AsyncGenerator<VisitorFingerprintSummary, void, void>;
  };

  readonly organizations: {
    create: (body: CreateOrganizationRequest) => Promise<Organization>;
    get: (organizationId: string, options?: RequestOptions) => Promise<Organization>;
    update: (organizationId: string, body: UpdateOrganizationRequest) => Promise<Organization>;
    apiKeys: {
      create: (organizationId: string, body: CreateApiKeyRequest) => Promise<IssuedApiKey>;
      list: (organizationId: string, params?: ApiKeyListParams) => Promise<ListResult<ApiKey>>;
      update: (organizationId: string, keyId: string, body: UpdateApiKeyRequest) => Promise<ApiKey>;
      revoke: (organizationId: string, keyId: string, options?: RequestOptions) => Promise<ApiKey>;
      rotate: (organizationId: string, keyId: string, options?: RequestOptions) => Promise<IssuedApiKey>;
    };
  };

  readonly gate: {
    registry: {
      list: (options?: RequestOptions) => Promise<GateRegistryEntry[]>;
      get: (serviceId: string, options?: RequestOptions) => Promise<GateRegistryEntry>;
    };
    services: {
      list: (options?: RequestOptions) => Promise<GateManagedService[]>;
      get: (serviceId: string, options?: RequestOptions) => Promise<GateManagedService>;
      create: (body: CreateGateServiceRequest) => Promise<GateManagedService>;
      update: (serviceId: string, body: UpdateGateServiceRequest) => Promise<GateManagedService>;
      disable: (serviceId: string, options?: RequestOptions) => Promise<GateManagedService>;
    };
    sessions: {
      create: (body: CreateGateSessionRequest) => Promise<GateSessionCreate>;
      poll: (gateSessionId: string, options: PollGateSessionOptions) => Promise<GateSessionPollData>;
      acknowledge: (
        gateSessionId: string,
        body: AcknowledgeGateSessionDeliveryRequest,
      ) => Promise<GateSessionDeliveryAcknowledgement>;
    };
    loginSessions: {
      create: (body: CreateGateLoginSessionRequest) => Promise<GateLoginSession>;
      consume: (body: ConsumeGateLoginSessionRequest) => Promise<GateDashboardLogin>;
    };
    agentTokens: {
      verify: (body: VerifyGateAgentTokenRequest) => Promise<AgentTokenVerification>;
      revoke: (body: RevokeGateAgentTokenRequest) => Promise<void>;
    };
  };

  readonly webhooks: {
    listEndpoints: (organizationId: string, options?: RequestOptions) => Promise<ListResult<WebhookEndpoint>>;
    createEndpoint: (organizationId: string, body: CreateWebhookEndpointRequest) => Promise<WebhookEndpoint>;
    updateEndpoint: (organizationId: string, endpointId: string, body: UpdateWebhookEndpointRequest) => Promise<WebhookEndpoint>;
    disableEndpoint: (organizationId: string, endpointId: string, options?: RequestOptions) => Promise<WebhookEndpoint>;
    rotateSecret: (organizationId: string, endpointId: string, options?: RequestOptions) => Promise<WebhookEndpoint>;
    sendTest: (organizationId: string, endpointId: string, options?: RequestOptions) => Promise<WebhookTest>;
    listEvents: (organizationId: string, params?: EventListParams) => Promise<ListResult<Event>>;
    retrieveEvent: (organizationId: string, eventId: string, options?: RequestOptions) => Promise<Event>;
  };

  constructor(options: TripwireOptions = {}) {
    this.http = new HttpClient(resolveOptions(options));

    this.sessions = {
      list: async (params = {}) => {
        const { signal, ...query } = params;
        const response = await this.http.request<ResourceListEnvelope<SessionSummary>>({
          path: '/v1/sessions',
          query,
          signal,
        });
        return normalizeListEnvelope(response);
      },
      get: async (sessionId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<SessionDetail>>({
          path: `/v1/sessions/${encodeURIComponent(sessionId)}`,
          signal: options.signal,
        });
        return response.data;
      },
      iter: async function* (params = {}) {
        yield* iterateCursor<SessionSummary, SessionListParams>(this.list, params);
      },
    };
    this.sessions.iter = this.sessions.iter.bind(this.sessions);

    this.fingerprints = {
      list: async (params = {}) => {
        const { signal, ...query } = params;
        const response = await this.http.request<ResourceListEnvelope<VisitorFingerprintSummary>>({
          path: '/v1/fingerprints',
          query,
          signal,
        });
        return normalizeListEnvelope(response);
      },
      get: async (visitorId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<VisitorFingerprintDetail>>({
          path: `/v1/fingerprints/${encodeURIComponent(visitorId)}`,
          signal: options.signal,
        });
        return response.data;
      },
      iter: async function* (params = {}) {
        yield* iterateCursor<VisitorFingerprintSummary, FingerprintListParams>(this.list, params);
      },
    };
    this.fingerprints.iter = this.fingerprints.iter.bind(this.fingerprints);

    this.organizations = {
      create: async (body) => {
        const { signal, ...payload } = body;
        const response = await this.http.request<ResourceEnvelope<Organization>>({
          path: '/v1/organizations',
          method: 'POST',
          body: payload,
          signal,
        });
        return response.data;
      },
      get: async (organizationId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<Organization>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}`,
          signal: options.signal,
        });
        return response.data;
      },
      update: async (organizationId, body) => {
        const { signal, ...payload } = body;
        const response = await this.http.request<ResourceEnvelope<Organization>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}`,
          method: 'PATCH',
          body: payload,
          signal,
        });
        return response.data;
      },
      apiKeys: {
        create: async (organizationId, body) => {
          const { signal, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<IssuedApiKey>>({
            path: `/v1/organizations/${encodeURIComponent(organizationId)}/api-keys`,
            method: 'POST',
            body: payload,
            signal,
          });
          return response.data;
        },
        list: async (organizationId, params = {}) => {
          const { signal, ...query } = params;
          const response = await this.http.request<ResourceListEnvelope<ApiKey>>({
            path: `/v1/organizations/${encodeURIComponent(organizationId)}/api-keys`,
            query,
            signal,
          });
          return normalizeListEnvelope(response);
        },
        update: async (organizationId, keyId, body) => {
          const { signal, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<ApiKey>>({
            path: `/v1/organizations/${encodeURIComponent(organizationId)}/api-keys/${encodeURIComponent(keyId)}`,
            method: 'PATCH',
            body: payload,
            signal,
          });
          return response.data;
        },
        revoke: async (organizationId, keyId, options = {}) => {
          const response = await this.http.request<ResourceEnvelope<ApiKey>>({
            path: `/v1/organizations/${encodeURIComponent(organizationId)}/api-keys/${encodeURIComponent(keyId)}`,
            method: 'DELETE',
            signal: options.signal,
          });
          return response.data;
        },
        rotate: async (organizationId, keyId, options = {}) => {
          const response = await this.http.request<ResourceEnvelope<IssuedApiKey>>({
            path: `/v1/organizations/${encodeURIComponent(organizationId)}/api-keys/${encodeURIComponent(keyId)}/rotations`,
            method: 'POST',
            signal: options.signal,
          });
          return response.data;
        },
      },
    };

    this.gate = {
      registry: {
        list: async (options = {}) => {
          const response = await this.http.request<ResourceEnvelope<GateRegistryEntry[]>>({
            path: '/v1/gate/registry',
            signal: options.signal,
            auth: { kind: 'none' },
          });
          return response.data;
        },
        get: async (serviceId, options = {}) => {
          const response = await this.http.request<ResourceEnvelope<GateRegistryEntry>>({
            path: `/v1/gate/registry/${encodeURIComponent(serviceId)}`,
            signal: options.signal,
            auth: { kind: 'none' },
          });
          return response.data;
        },
      },
      services: {
        list: async (options = {}) => {
          const response = await this.http.request<ResourceEnvelope<GateManagedService[]>>({
            path: '/v1/gate/services',
            signal: options.signal,
          });
          return response.data;
        },
        get: async (serviceId, options = {}) => {
          const response = await this.http.request<ResourceEnvelope<GateManagedService>>({
            path: `/v1/gate/services/${encodeURIComponent(serviceId)}`,
            signal: options.signal,
          });
          return response.data;
        },
        create: async (body) => {
          const { signal, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<GateManagedService>>({
            path: '/v1/gate/services',
            method: 'POST',
            body: payload,
            signal,
          });
          return response.data;
        },
        update: async (serviceId, body) => {
          const { signal, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<GateManagedService>>({
            path: `/v1/gate/services/${encodeURIComponent(serviceId)}`,
            method: 'PATCH',
            body: payload,
            signal,
          });
          return response.data;
        },
        disable: async (serviceId, options = {}) => {
          const response = await this.http.request<ResourceEnvelope<GateManagedService>>({
            path: `/v1/gate/services/${encodeURIComponent(serviceId)}`,
            method: 'DELETE',
            signal: options.signal,
          });
          return response.data;
        },
      },
      sessions: {
        create: async (body) => {
          const { signal, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<GateSessionCreate>>({
            path: '/v1/gate/sessions',
            method: 'POST',
            body: payload,
            signal,
            auth: { kind: 'none' },
          });
          return response.data;
        },
        poll: async (gateSessionId, options) => {
          const response = await this.http.request<ResourceEnvelope<GateSessionPollData>>({
            path: `/v1/gate/sessions/${encodeURIComponent(gateSessionId)}`,
            signal: options.signal,
            auth: { kind: 'bearer', token: options.pollToken },
          });
          return response.data;
        },
        acknowledge: async (gateSessionId, body) => {
          const { signal, pollToken, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<GateSessionDeliveryAcknowledgement>>({
            path: `/v1/gate/sessions/${encodeURIComponent(gateSessionId)}/ack`,
            method: 'POST',
            body: payload,
            signal,
            auth: { kind: 'bearer', token: pollToken },
          });
          return response.data;
        },
      },
      loginSessions: {
        create: async (body) => {
          const { signal, agentToken, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<GateLoginSession>>({
            path: '/v1/gate/login-sessions',
            method: 'POST',
            body: payload,
            signal,
            auth: { kind: 'bearer', token: agentToken },
          });
          return response.data;
        },
        consume: async (body) => {
          const { signal, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<GateDashboardLogin>>({
            path: '/v1/gate/login-sessions/consume',
            method: 'POST',
            body: payload,
            signal,
          });
          return response.data;
        },
      },
      agentTokens: {
        verify: async (body) => {
          const { signal, ...payload } = body;
          const response = await this.http.request<ResourceEnvelope<AgentTokenVerification>>({
            path: '/v1/gate/agent-tokens/verify',
            method: 'POST',
            body: payload,
            signal,
          });
          return response.data;
        },
        revoke: async (body) => {
          const { signal, ...payload } = body;
          await this.http.request<void>({
            path: '/v1/gate/agent-tokens/revoke',
            method: 'POST',
            body: payload,
            signal,
          });
        },
      },
    };

    this.webhooks = {
      listEndpoints: async (organizationId, options = {}) => {
        const response = await this.http.request<ResourceListEnvelope<WebhookEndpoint>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}/webhooks/endpoints`,
          signal: options.signal,
        });
        return normalizeListEnvelope(response);
      },
      createEndpoint: async (organizationId, body) => {
        const { signal, ...payload } = body;
        const response = await this.http.request<ResourceEnvelope<WebhookEndpoint>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}/webhooks/endpoints`,
          method: 'POST',
          body: payload,
          signal,
        });
        return response.data;
      },
      updateEndpoint: async (organizationId, endpointId, body) => {
        const { signal, ...payload } = body;
        const response = await this.http.request<ResourceEnvelope<WebhookEndpoint>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}/webhooks/endpoints/${encodeURIComponent(endpointId)}`,
          method: 'PATCH',
          body: payload,
          signal,
        });
        return response.data;
      },
      disableEndpoint: async (organizationId, endpointId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<WebhookEndpoint>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}/webhooks/endpoints/${encodeURIComponent(endpointId)}`,
          method: 'DELETE',
          signal: options.signal,
        });
        return response.data;
      },
      rotateSecret: async (organizationId, endpointId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<WebhookEndpoint>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}/webhooks/endpoints/${encodeURIComponent(endpointId)}/rotations`,
          method: 'POST',
          signal: options.signal,
        });
        return response.data;
      },
      sendTest: async (organizationId, endpointId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<WebhookTest>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}/webhooks/endpoints/${encodeURIComponent(endpointId)}/test`,
          method: 'POST',
          signal: options.signal,
        });
        return response.data;
      },
      listEvents: async (organizationId, params = {}) => {
        const { signal, ...query } = params;
        const response = await this.http.request<ResourceListEnvelope<Event>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}/events`,
          query,
          signal,
        });
        return normalizeListEnvelope(response);
      },
      retrieveEvent: async (organizationId, eventId, options = {}) => {
        const response = await this.http.request<ResourceEnvelope<Event>>({
          path: `/v1/organizations/${encodeURIComponent(organizationId)}/events/${encodeURIComponent(eventId)}`,
          signal: options.signal,
        });
        return response.data;
      },
    };
  }
}
