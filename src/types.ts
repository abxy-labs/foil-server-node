export interface TripwireOptions {
  secretKey?: string;
  baseUrl?: string;
  timeoutMs?: number;
  fetch?: typeof globalThis.fetch;
  userAgent?: string;
}

export interface RequestOptions {
  signal?: AbortSignal;
}

export interface ListResult<T> {
  items: T[];
  limit: number;
  has_more: boolean;
  next_cursor?: string;
}

export interface CursorPagination {
  limit: number;
  has_more: boolean;
  next_cursor?: string;
}

export interface ResponseMeta {
  request_id: string;
}

export interface TripwireFieldError {
  name: string;
  issue: string;
  expected?: string;
  received?: string | number | boolean | null;
}

export interface TripwireErrorDetails {
  fields?: TripwireFieldError[];
  allowed_values?: string[];
  header_name?: string;
  parameter_set?: string;
  next_action?: 'retry' | 'new_session' | 'reload_bundle' | 'contact_support';
  [key: string]: unknown;
}

export interface ApiErrorBody {
  code: string;
  message: string;
  status: number;
  retryable: boolean;
  request_id: string;
  docs_url?: string;
  details?: TripwireErrorDetails;
}

export interface ApiErrorEnvelope {
  error: ApiErrorBody;
}

export interface Decision {
  event_id: string;
  verdict: 'bot' | 'human' | 'inconclusive';
  risk_score: number;
  phase: 'snapshot' | 'behavioral' | null;
  is_provisional: boolean | null;
  manipulation: {
    score: number | null;
    verdict: 'none' | 'low' | 'medium' | 'high' | null;
  } | null;
  evaluation_duration_ms: number | null;
  evaluated_at: string;
}

export interface RequestContext {
  user_agent: string;
  url: string;
  screen_size: string | null;
  is_touch_capable: boolean | null;
  ip_address: string;
}

export interface SessionDetailRequest {
  url: string;
  referrer: string | null;
  user_agent: string;
}

export interface SessionBrowser {
  name: string | null;
  version: string | null;
  major_version: string | null;
  engine: 'blink' | 'gecko' | 'webkit' | 'unknown';
}

export interface SessionDevice {
  form_factor: 'desktop' | 'phone' | 'tablet' | 'unknown';
  operating_system: {
    name: string | null;
    version: string | null;
  };
  architecture: string | null;
  screen: {
    size: string | null;
    color_depth: number | null;
    pixel_ratio: number | null;
    orientation_type: string | null;
  };
  locale: {
    timezone: string | null;
    primary_language: string | null;
    languages: string[];
  };
  capabilities: {
    touch: {
      available: boolean | null;
      max_touch_points: number | null;
    };
    storage: {
      cookies: boolean | null;
      local_storage: boolean | null;
      indexed_db: boolean | null;
      service_worker: boolean | null;
      window_name: boolean | null;
    };
    webgpu: {
      available: boolean | null;
    };
    platform_authenticator: {
      available: boolean | null;
      conditional_mediation: boolean | null;
    };
    media_devices: {
      available: boolean | null;
    };
    speech_synthesis: {
      available: boolean | null;
    };
  };
}

export interface SessionNetwork {
  ip_address: string | null;
  ip_version: 'ipv4' | 'ipv6' | null;
  status: 'pending' | 'ready' | 'skipped' | 'error';
  summary: string | null;
  location: {
    city: string | null;
    region: string | null;
    country: string | null;
    country_code: string | null;
    latitude: number | null;
    longitude: number | null;
    timezone: string | null;
    postal_code: string | null;
    accuracy_radius_km: number | null;
  } | null;
  routing: {
    asn: string | null;
    organization: string | null;
  };
  anonymity: {
    vpn: boolean;
    proxy: boolean;
    tor: boolean;
    relay: boolean;
    hosting: boolean;
    residential_proxy: boolean;
    callback_proxy: boolean;
    provider: string | null;
  };
  reputation: {
    listed: boolean;
    categories: string[];
    suspicious_network: boolean;
  };
  evidence: {
    risk_signals: string[];
    operator_tags: string[];
    client_types: string[];
    client_count: number | null;
  };
  evaluated_at: string | null;
}

export type ObservationHash = string | number | null;

export interface SessionClientTelemetry {
  navigator: {
    platform: string | null;
    vendor: string | null;
    hardware_concurrency: number | null;
    device_memory: number | null;
    max_touch_points: number | null;
    pdf_viewer_enabled: boolean | null;
    cookie_enabled: boolean | null;
    product_sub: string | null;
    primary_language: string | null;
    languages: string[];
    mime_types_count: number | null;
    plugins: string[];
  };
  storage: {
    cookies: boolean | null;
    local_storage: boolean | null;
    session_storage: boolean | null;
    indexed_db: boolean | null;
    service_worker: boolean | null;
    window_name: boolean | null;
  };
  canvas: {
    hash: ObservationHash;
    geometry_hash: ObservationHash;
    text_hash: ObservationHash;
    winding: boolean | null;
    noise_detected: boolean | null;
    offscreen_consistent: boolean | null;
  };
  graphics: {
    webgl: {
      vendor: string | null;
      renderer: string | null;
      version: string | null;
      shading_language_version: string | null;
      parameters_hash: ObservationHash;
      extensions_hash: ObservationHash;
      extension_parameters_hash: ObservationHash;
      shader_precision_hash: ObservationHash;
    };
    webgpu: {
      available: boolean | null;
      adapter_vendor: string | null;
      adapter_architecture: string | null;
      fallback_adapter: boolean | null;
      features_hash: ObservationHash;
      limits_hash: ObservationHash;
    };
  };
  audio: {
    hash: ObservationHash;
    sample_rate: number | null;
    channel_count: number | null;
    voice_count: number | null;
    local_voice_count: number | null;
    default_voice_lang: string | null;
    noise_detected: boolean | null;
  };
  fonts: {
    detected_count: number | null;
    tested_count: number | null;
    enumeration_hash: ObservationHash;
    metrics_hash: ObservationHash;
    preferences_hash: ObservationHash;
    emoji_hash: ObservationHash;
  };
  media: {
    device_count: number | null;
    counts_by_kind: Record<string, number>;
    blank_label_count: number | null;
    topology_hash: ObservationHash;
  };
}

export interface SessionHighlightEvidence {
  signal: string;
  name: string;
}

export interface SessionHighlight {
  key: string;
  effect: 'increases_risk' | 'reduces_risk' | 'context';
  importance: 'high' | 'medium' | 'low';
  summary: string;
  evidence?: SessionHighlightEvidence[];
}

export interface SessionDecision {
  event_id: string;
  automation_status: 'automated' | 'human' | 'uncertain';
  risk_score: number;
  evaluation_phase: 'snapshot' | 'behavioral' | null;
  decision_status: 'preliminary' | 'final';
  evaluated_at: string;
}

export interface SessionAutomationFacet {
  value: string;
  confidence: number;
  relation: string;
}

export interface SessionAutomation {
  category: string | null;
  confidence: number | null;
  provider: string | null;
  product: string | null;
  framework: string | null;
  concealment_style: string | null;
  organization: string | null;
  facets: Record<string, SessionAutomationFacet>;
}

export interface SessionWebBotAuth {
  status: string | null;
  domain: string | null;
}

export interface SessionRuntimeIntegrity {
  tampering_detected: boolean;
  developer_tools_detected: boolean;
  emulation_suspected: boolean;
  virtualization_suspected: boolean;
  privacy_hardening_suspected: boolean;
  identity_spoofing_suspected: boolean;
  replay_suspected: boolean;
  outdated_environment: boolean;
  verified_bot_identity: boolean;
}

export interface VisitorFingerprintLink {
  object: 'visitor_fingerprint';
  id: string;
  confidence: number | null;
  identified_at: string | null;
}

export interface SessionDetailVisitorFingerprint {
  object: 'visitor_fingerprint';
  id: string;
  confidence: number | null;
  identified_at: string | null;
  lifecycle: {
    first_seen_at: string | null;
    last_seen_at: string | null;
    seen_count: number | null;
  };
}

export interface SessionConnectionFingerprint {
  ja4: {
    hash: string | null;
    profile: string | null;
    family: string | null;
    product: string | null;
    confidence: string | null;
    deterministic: boolean | null;
  };
  http2: {
    akamai_fingerprint: string | null;
    profile: string | null;
  };
  user_agent_alignment: 'match' | 'mismatch' | 'unknown' | null;
}

export interface SessionAnalysisCoverage {
  browser: boolean;
  device: boolean;
  network: boolean;
  runtime: boolean;
  behavioral: boolean;
  visitor_identity: boolean;
}

export interface SessionSignalFired {
  signal: string;
  role: string;
  category: string;
  strength: string;
  signal_score: number;
}

export interface SessionSummary {
  object: 'session';
  id: string;
  created_at: string | null;
  latest_decision: Decision;
  visitor_fingerprint: VisitorFingerprintLink | null;
}

export interface SessionDetail {
  object: 'session';
  id: string;
  created_at: string | null;
  decision: SessionDecision;
  highlights: SessionHighlight[];
  automation: SessionAutomation | null;
  web_bot_auth: SessionWebBotAuth | null;
  network: SessionNetwork;
  runtime_integrity: SessionRuntimeIntegrity;
  native_runtime_integrity: Record<string, unknown> | null;
  native_app: Record<string, unknown> | null;
  native_carrier: Record<string, unknown> | null;
  native_motion_print: Record<string, unknown> | null;
  device_identity: Record<string, unknown> | null;
  install_id: string | null;
  visitor_fingerprint: SessionDetailVisitorFingerprint | null;
  connection_fingerprint: SessionConnectionFingerprint;
  previous_decisions: SessionDecision[];
  request: SessionDetailRequest;
  browser: SessionBrowser;
  device: SessionDevice;
  analysis_coverage: SessionAnalysisCoverage;
  signals_fired: SessionSignalFired[];
  client_telemetry: SessionClientTelemetry;
}

export interface VisitorFingerprintSummary {
  object: 'visitor_fingerprint';
  id: string;
  lifecycle: {
    first_seen_at: string;
    last_seen_at: string;
    seen_count: number;
    expires_at: string;
  };
  latest_request: {
    user_agent: string;
    ip_address: string;
  };
  storage: {
    cookies: boolean;
    local_storage: boolean;
    indexed_db: boolean;
    service_worker: boolean;
    window_name: boolean;
  };
  anchors: {
    webgl_hash: string | null;
    parameters_hash: string | null;
    audio_hash: string | null;
  };
}

export interface VisitorFingerprintActivitySession {
  session_id: string;
  decision: Decision;
  request: RequestContext;
  score_breakdown: {
    categories: Record<string, number> | null;
  };
}

export interface VisitorFingerprintDetail extends VisitorFingerprintSummary {
  components: {
    vector: number[] | null;
  };
  activity: {
    sessions: VisitorFingerprintActivitySession[];
  };
}

export interface Organization {
  object: 'organization';
  id: string;
  name: string;
  slug: string;
  status: 'active' | 'suspended' | 'deleted';
  created_at: string;
  updated_at: string | null;
}

export interface ApiKey {
  object: 'api_key';
  id: string;
  type: 'publishable' | 'secret';
  name: string;
  environment: 'live' | 'test';
  allowed_origins: string[] | null;
  scopes: string[] | null;
  rate_limit: number | null;
  status: 'active' | 'rotating' | 'revoked';
  key_preview: string;
  display_key?: string;
  revealed_key?: string;
  last_used_at: string | null;
  created_at: string;
  rotated_at: string | null;
  revoked_at: string | null;
  grace_expires_at: string | null;
}

export interface IssuedApiKey extends ApiKey {
  revealed_key: string;
}

export type GateServiceStatus = 'active' | 'disabled';

export interface GateServiceEnvVar {
  name: string;
  key: string;
  secret: boolean;
}

export interface GateServiceSdkInstall {
  label: string;
  install: string;
  url: string;
}

export interface GateServiceBranding {
  logo_url?: string;
  primary_color?: string;
  secondary_color?: string;
  ascii_art?: string;
  verified: boolean;
}

export interface GateServiceBrandingInput {
  logo_url?: string;
  primary_color?: string;
  secondary_color?: string;
  ascii_art?: string;
}

export interface GateServiceConsent {
  terms_url?: string;
  privacy_url?: string;
}

export interface GateRegistryEntry {
  id: string;
  status: GateServiceStatus;
  discoverable: boolean;
  name: string;
  description: string;
  website: string;
  dashboard_login_url?: string;
  env_vars: GateServiceEnvVar[];
  docs_url: string;
  sdks: GateServiceSdkInstall[];
  branding: GateServiceBranding;
  consent: GateServiceConsent;
}

export interface GateManagedService extends GateRegistryEntry {
  object: 'gate_service';
  webhook_endpoint_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface GateDeliveryRequest {
  version: 1;
  algorithm: 'x25519-hkdf-sha256/aes-256-gcm';
  key_id: string;
  public_key: string;
}

export interface GateDeliveryEnvelope {
  version: 1;
  algorithm: 'x25519-hkdf-sha256/aes-256-gcm';
  key_id: string;
  ephemeral_public_key: string;
  salt: string;
  iv: string;
  ciphertext: string;
  tag: string;
}

export interface GateDeliveryBundle {
  integrator: GateDeliveryEnvelope;
  gate: GateDeliveryEnvelope;
}

export interface GateSessionCreate {
  object: 'gate_session';
  id: string;
  status: 'pending';
  poll_token: string;
  consent_url: string;
  expires_at: string;
}

export interface GateSessionPollData {
  object: 'gate_session';
  id: string;
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  expires_at?: string;
  gate_account_id?: string;
  account_name?: string;
  delivery_bundle?: GateDeliveryBundle;
  docs_url?: string;
}

export interface GateSessionDeliveryAcknowledgement {
  object: 'gate_session_delivery';
  gate_session_id: string;
  status: 'acknowledged';
}

export interface GateLoginSession {
  object: 'gate_login_session';
  id: string;
  status: 'pending';
  consent_url: string;
  expires_at: string;
}

export interface GateDashboardLogin {
  object: 'gate_dashboard_login';
  gate_account_id: string;
  account_name: string;
}

export interface AgentTokenVerification {
  valid: boolean;
  gate_account_id?: string;
  status?: 'active' | 'revoked';
  created_at?: string;
  expires_at?: string;
}

export interface SessionListParams extends RequestOptions {
  limit?: number;
  cursor?: string;
  verdict?: 'bot' | 'human' | 'inconclusive';
  search?: string;
}

export interface FingerprintListParams extends RequestOptions {
  limit?: number;
  cursor?: string;
  search?: string;
  sort?: 'seen_count' | 'first_seen';
}

export interface ApiKeyListParams extends RequestOptions {
  limit?: number;
  cursor?: string;
}

export interface CreateOrganizationRequest extends RequestOptions {
  name: string;
  slug: string;
}

export interface UpdateOrganizationRequest extends RequestOptions {
  name?: string;
  status?: 'active' | 'suspended' | 'deleted';
}

export interface CreateApiKeyRequest extends RequestOptions {
  name: string;
  type?: 'publishable' | 'secret';
  environment?: 'live' | 'test';
  allowed_origins?: string[];
  scopes?: string[];
}

export interface UpdateApiKeyRequest extends RequestOptions {
  name?: string;
  allowed_origins?: string[];
  scopes?: string[];
}

export interface CreateGateServiceRequest extends RequestOptions {
  id: string;
  discoverable?: boolean;
  name: string;
  description: string;
  website: string;
  dashboard_login_url?: string;
  webhook_endpoint_id: string;
  env_vars?: GateServiceEnvVar[];
  docs_url?: string;
  sdks?: GateServiceSdkInstall[];
  branding?: GateServiceBrandingInput;
  consent?: GateServiceConsent;
}

export interface UpdateGateServiceRequest extends RequestOptions {
  discoverable?: boolean;
  name?: string;
  description?: string;
  website?: string;
  dashboard_login_url?: string | null;
  webhook_endpoint_id?: string;
  env_vars?: GateServiceEnvVar[];
  docs_url?: string;
  sdks?: GateServiceSdkInstall[];
  branding?: GateServiceBrandingInput;
  consent?: GateServiceConsent;
}

export type WebhookEventType =
  | 'session.fingerprint.calculated'
  | 'session.result.persisted'
  | 'gate.session.approved';

export type WebhookDeliveryEventType = WebhookEventType | 'webhook.test';
export type WebhookEndpointStatus = 'active' | 'disabled';
export type WebhookDeliveryStatus = 'pending' | 'delivering' | 'succeeded' | 'failed' | 'skipped';

export interface WebhookEndpoint {
  object: 'webhook_endpoint';
  id: string;
  name: string;
  url: string;
  status: WebhookEndpointStatus;
  event_types: WebhookEventType[];
  signing_secret?: string;
  created_at: string;
  updated_at: string;
}

export interface WebhookDelivery {
  object: 'webhook_delivery';
  id: string;
  event_id: string;
  endpoint_id: string;
  event_type: WebhookDeliveryEventType;
  status: WebhookDeliveryStatus;
  attempts: number;
  response_status: number | null;
  response_body: string | null;
  error: string | null;
  created_at: string;
  updated_at: string;
}

export interface WebhookTest {
  object: 'webhook_test';
  event_id: string;
  delivery_ids: string[];
  latest_delivery: WebhookDelivery | null;
}

export interface CreateWebhookEndpointRequest extends RequestOptions {
  name: string;
  url: string;
  event_types: WebhookEventType[];
}

export interface UpdateWebhookEndpointRequest extends RequestOptions {
  name?: string;
  url?: string;
  status?: WebhookEndpointStatus;
  event_types?: WebhookEventType[];
}

export interface EventSubject {
  type: string;
  id: string;
}

export interface Event {
  object: 'event';
  id: string;
  type: WebhookDeliveryEventType;
  subject: EventSubject;
  data: Record<string, unknown>;
  webhook_deliveries: WebhookDelivery[];
  created_at: string;
}

export interface EventListParams extends RequestOptions {
  endpoint_id?: string;
  type?: WebhookDeliveryEventType;
  limit?: number;
}

export interface SessionFingerprintCalculatedPayload {
  object: 'session_fingerprint';
  session: { id: string };
  visitor_fingerprint: { id: string; confidence: number | null; identified_at: string | null };
  request: Record<string, unknown>;
  calculated_at: string;
}

export interface SessionResultPersistedPayload {
  object: 'session_result';
  session: { id: string };
  event: Record<string, unknown>;
  decision: Record<string, unknown>;
  visitor_fingerprint: { id: string } | null;
  request: Record<string, unknown>;
  score_breakdown: Record<string, unknown>;
  signals: Array<Record<string, unknown>>;
  attribution: Record<string, unknown>;
}

export interface GateSessionApprovedPayload {
  service_id: string;
  gate_session_id: string;
  gate_account_id: string;
  account_name: string;
  metadata: Record<string, unknown> | null;
  tripwire: { verdict: 'bot' | 'human' | 'inconclusive'; score: number | null };
  delivery: GateDeliveryRequest;
}

export type WebhookEventPayload =
  | SessionFingerprintCalculatedPayload
  | SessionResultPersistedPayload
  | GateSessionApprovedPayload
  | Record<string, unknown>;

export interface WebhookEventEnvelope<TData = WebhookEventPayload> {
  id: string;
  object: 'webhook_event';
  type: WebhookDeliveryEventType;
  created: string;
  data: TData;
}

export interface CreateGateSessionRequest extends RequestOptions {
  service_id: string;
  account_name: string;
  metadata?: Record<string, unknown>;
  delivery: GateDeliveryRequest;
}

export interface PollGateSessionOptions extends RequestOptions {
  pollToken: string;
}

export interface AcknowledgeGateSessionDeliveryRequest extends RequestOptions {
  pollToken: string;
  ack_token: string;
}

export interface CreateGateLoginSessionRequest extends RequestOptions {
  service_id: string;
  agentToken: string;
}

export interface ConsumeGateLoginSessionRequest extends RequestOptions {
  code: string;
}

export interface VerifyGateAgentTokenRequest extends RequestOptions {
  agent_token: string;
}

export interface RevokeGateAgentTokenRequest extends RequestOptions {
  agent_token: string;
}

export interface VerifiedTripwireSignal {
  id: string;
  category: string;
  confidence: string;
  score: number;
  [key: string]: unknown;
}

export interface VerifiedTripwireToken {
  object: 'session_verification';
  session_id: string;
  decision: Decision;
  request: RequestContext;
  visitor_fingerprint: VisitorFingerprintLink | null;
  signals: VerifiedTripwireSignal[];
  score_breakdown: {
    categories: Record<string, number>;
  };
  attribution: {
    bot: Record<string, unknown> | null;
    [key: string]: unknown;
  };
  embed: Record<string, unknown> | null;
  [key: string]: unknown;
}

export interface SafeVerifyTripwireTokenSuccess {
  ok: true;
  data: VerifiedTripwireToken;
}

export interface SafeVerifyTripwireTokenFailure {
  ok: false;
  error: Error;
}

export type SafeVerifyTripwireTokenResult =
  | SafeVerifyTripwireTokenSuccess
  | SafeVerifyTripwireTokenFailure;

export interface ResourceEnvelope<T> {
  data: T;
  meta: ResponseMeta;
}

export interface ResourceListEnvelope<T> {
  data: T[];
  pagination: CursorPagination;
  meta: ResponseMeta;
}
