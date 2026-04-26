import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  hkdfSync,
  randomBytes,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto';
import type { GateDeliveryEnvelope, GateDeliveryRequest, WebhookEventEnvelope } from './types';

export const GATE_DELIVERY_VERSION = 1 as const;
export const GATE_DELIVERY_ALGORITHM = 'x25519-hkdf-sha256/aes-256-gcm' as const;
export const GATE_AGENT_TOKEN_ENV_SUFFIX = '_GATE_AGENT_TOKEN' as const;
export const BLOCKED_GATE_ENV_VAR_KEYS = [
  'BASH_ENV',
  'BROWSER',
  'CDPATH',
  'DYLD_INSERT_LIBRARIES',
  'DYLD_LIBRARY_PATH',
  'EDITOR',
  'ENV',
  'GIT_ASKPASS',
  'GIT_SSH_COMMAND',
  'HOME',
  'LD_LIBRARY_PATH',
  'LD_PRELOAD',
  'NODE_OPTIONS',
  'NODE_PATH',
  'PATH',
  'PERL5OPT',
  'PERLLIB',
  'PROMPT_COMMAND',
  'PYTHONHOME',
  'PYTHONPATH',
  'PYTHONSTARTUP',
  'RUBYLIB',
  'RUBYOPT',
  'SHELLOPTS',
  'SSH_ASKPASS',
  'VISUAL',
  'XDG_CONFIG_HOME',
] as const;
export const BLOCKED_GATE_ENV_VAR_PREFIXES = [
  'NPM_CONFIG_',
  'BUN_CONFIG_',
  'GIT_CONFIG_',
] as const;

const GATE_DELIVERY_HKDF_INFO = Buffer.from('tripwire-gate-delivery:v1', 'utf8');
const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');
const BLOCKED_GATE_ENV_VAR_KEY_SET = new Set<string>(BLOCKED_GATE_ENV_VAR_KEYS);

export interface GateDeliveryPayload {
  version: typeof GATE_DELIVERY_VERSION;
  outputs: Record<string, string>;
  ack_token?: string;
}

export interface GeneratedDeliveryKeyPair {
  delivery: GateDeliveryRequest;
  privateKey: KeyObject;
}

export interface GateEncryptedDeliveryResponse {
  encrypted_delivery: GateDeliveryEnvelope;
}

export interface GateDeliveryHelperInput {
  delivery: GateDeliveryRequest;
  outputs: Record<string, string>;
}

export interface GateApprovedWebhookPayload {
  service_id: string;
  gate_session_id: string;
  gate_account_id: string;
  account_name: string;
  metadata: Record<string, unknown> | null;
  tripwire: {
    verdict: 'bot' | 'human' | 'inconclusive';
    score: number | null;
  };
  delivery: GateDeliveryRequest;
}

export interface VerifyGateWebhookSignatureInput {
  secret: string;
  timestamp: string;
  rawBody: string;
  signature: string;
  maxAgeSeconds?: number;
  nowSeconds?: number;
}

export interface VerifyAndParseWebhookEventInput extends VerifyGateWebhookSignatureInput {}

function toBase64Url(value: Buffer | Uint8Array | string): string {
  return Buffer.from(value).toString('base64url');
}

function fromBase64Url(value: string, label: string): Buffer {
  try {
    return Buffer.from(value, 'base64url');
  } catch {
    throw new Error(`Invalid ${label}`);
  }
}

function createPublicKeyFromRawX25519(rawPublicKey: Buffer): KeyObject {
  if (rawPublicKey.length !== 32) {
    throw new Error('X25519 public key must be 32 bytes');
  }
  return createPublicKey({
    key: Buffer.concat([X25519_SPKI_PREFIX, rawPublicKey]),
    format: 'der',
    type: 'spki',
  });
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isGateVerdict(value: unknown): value is GateApprovedWebhookPayload['tripwire']['verdict'] {
  return value === 'bot' || value === 'human' || value === 'inconclusive';
}

export function deriveGateAgentTokenEnvKey(serviceId: string): string {
  const normalized = serviceId
    .trim()
    .replace(/[^A-Za-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
    .replace(/_+/g, '_')
    .toUpperCase();

  if (!normalized) {
    throw new Error('service_id is required to derive a Gate agent token env key');
  }

  return `${normalized}${GATE_AGENT_TOKEN_ENV_SUFFIX}`;
}

export function isGateManagedEnvVarKey(key: string): boolean {
  return key === 'TRIPWIRE_AGENT_TOKEN' || key.endsWith(GATE_AGENT_TOKEN_ENV_SUFFIX);
}

export function isBlockedGateEnvVarKey(key: string): boolean {
  const normalized = key.trim().toUpperCase();
  return BLOCKED_GATE_ENV_VAR_KEY_SET.has(normalized)
    || BLOCKED_GATE_ENV_VAR_PREFIXES.some((prefix) => normalized.startsWith(prefix));
}

export function rawX25519PublicKeyFromKeyObject(publicKey: KeyObject): Buffer {
  const der = publicKey.export({ format: 'der', type: 'spki' });
  if (!Buffer.isBuffer(der) || der.length !== X25519_SPKI_PREFIX.length + 32) {
    throw new Error('Unexpected X25519 public key encoding');
  }
  if (!der.subarray(0, X25519_SPKI_PREFIX.length).equals(X25519_SPKI_PREFIX)) {
    throw new Error('Unexpected X25519 public key prefix');
  }
  return der.subarray(X25519_SPKI_PREFIX.length);
}

export function keyIdForRawX25519PublicKey(rawPublicKey: Buffer): string {
  if (rawPublicKey.length !== 32) {
    throw new Error('X25519 public key must be 32 bytes');
  }
  return toBase64Url(createHash('sha256').update(rawPublicKey).digest());
}

export function createDeliveryKeyPair(): GeneratedDeliveryKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const rawPublicKey = rawX25519PublicKeyFromKeyObject(publicKey);
  return {
    delivery: {
      version: GATE_DELIVERY_VERSION,
      algorithm: GATE_DELIVERY_ALGORITHM,
      key_id: keyIdForRawX25519PublicKey(rawPublicKey),
      public_key: toBase64Url(rawPublicKey),
    },
    privateKey,
  };
}

export function exportDeliveryPrivateKeyPkcs8(privateKey: KeyObject): string {
  const der = privateKey.export({ format: 'der', type: 'pkcs8' });
  if (!Buffer.isBuffer(der)) {
    throw new Error('Unexpected X25519 private key encoding');
  }
  return toBase64Url(der);
}

export function importDeliveryPrivateKeyPkcs8(value: string): KeyObject {
  const der = fromBase64Url(value, 'delivery.private_key_pkcs8');
  return createPrivateKey({
    key: der,
    format: 'der',
    type: 'pkcs8',
  });
}

export function validateGateDeliveryRequest(value: unknown): GateDeliveryRequest {
  if (!value || typeof value !== 'object') {
    throw new Error('delivery must be an object');
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.version !== GATE_DELIVERY_VERSION) {
    throw new Error('delivery.version must be 1');
  }
  if (candidate.algorithm !== GATE_DELIVERY_ALGORITHM) {
    throw new Error(`delivery.algorithm must be ${GATE_DELIVERY_ALGORITHM}`);
  }
  if (typeof candidate.public_key !== 'string' || candidate.public_key.length === 0) {
    throw new Error('delivery.public_key is required');
  }
  if (typeof candidate.key_id !== 'string' || candidate.key_id.length === 0) {
    throw new Error('delivery.key_id is required');
  }
  const rawPublicKey = fromBase64Url(candidate.public_key, 'delivery.public_key');
  if (rawPublicKey.length !== 32) {
    throw new Error('delivery.public_key must be a raw X25519 public key');
  }
  if (keyIdForRawX25519PublicKey(rawPublicKey) !== candidate.key_id) {
    throw new Error('delivery.key_id does not match delivery.public_key');
  }
  return {
    version: GATE_DELIVERY_VERSION,
    algorithm: GATE_DELIVERY_ALGORITHM,
    key_id: candidate.key_id,
    public_key: candidate.public_key,
  };
}

export function createEncryptedDeliveryResponse(
  input: GateDeliveryHelperInput,
): GateEncryptedDeliveryResponse {
  return {
    encrypted_delivery: encryptGateDeliveryPayload(input.delivery, {
      version: GATE_DELIVERY_VERSION,
      outputs: input.outputs,
    }),
  };
}

export function createGateApprovedWebhookResponse(
  input: GateDeliveryHelperInput,
): GateEncryptedDeliveryResponse {
  return createEncryptedDeliveryResponse(input);
}

export function validateGateApprovedWebhookPayload(value: unknown): GateApprovedWebhookPayload {
  if (!isPlainObject(value)) {
    throw new Error('webhook payload must be an object');
  }
  if ('event' in value) {
    throw new Error('webhook payload must not include event; use the webhook event envelope type');
  }
  if (typeof value.service_id !== 'string' || value.service_id.length === 0) {
    throw new Error('service_id is required');
  }
  if (typeof value.gate_session_id !== 'string' || value.gate_session_id.length === 0) {
    throw new Error('gate_session_id is required');
  }
  if (typeof value.gate_account_id !== 'string' || value.gate_account_id.length === 0) {
    throw new Error('gate_account_id is required');
  }
  if (typeof value.account_name !== 'string' || value.account_name.length === 0) {
    throw new Error('account_name is required');
  }
  if (value.metadata !== null && value.metadata !== undefined && !isPlainObject(value.metadata)) {
    throw new Error('metadata must be an object or null');
  }
  if (!isPlainObject(value.tripwire)) {
    throw new Error('tripwire must be an object');
  }
  if (!isGateVerdict(value.tripwire.verdict)) {
    throw new Error('tripwire.verdict is invalid');
  }
  if (value.tripwire.score != null && typeof value.tripwire.score !== 'number') {
    throw new Error('tripwire.score must be a number or null');
  }
  return {
    service_id: value.service_id,
    gate_session_id: value.gate_session_id,
    gate_account_id: value.gate_account_id,
    account_name: value.account_name,
    metadata: value.metadata && isPlainObject(value.metadata) ? value.metadata : null,
    tripwire: {
      verdict: value.tripwire.verdict,
      score: value.tripwire.score ?? null,
    },
    delivery: validateGateDeliveryRequest(value.delivery),
  };
}

export function verifyGateWebhookSignature(input: VerifyGateWebhookSignatureInput): boolean {
  const parsedTimestamp = Number.parseInt(input.timestamp, 10);
  if (!Number.isFinite(parsedTimestamp)) {
    return false;
  }
  const nowSeconds = input.nowSeconds ?? Math.floor(Date.now() / 1000);
  const maxAgeSeconds = input.maxAgeSeconds ?? 5 * 60;
  if (Math.abs(nowSeconds - parsedTimestamp) > maxAgeSeconds) {
    return false;
  }
  const expected = createHmac('sha256', input.secret)
    .update(`${input.timestamp}.${input.rawBody}`)
    .digest('hex');
  const expectedBuffer = Buffer.from(expected, 'utf8');
  const receivedBuffer = Buffer.from(input.signature, 'utf8');
  if (expectedBuffer.length !== receivedBuffer.length) {
    return false;
  }
  return timingSafeEqual(expectedBuffer, receivedBuffer);
}

export function parseWebhookEvent(rawBody: string | Buffer | Uint8Array | unknown): WebhookEventEnvelope {
  const value = typeof rawBody === 'string' || rawBody instanceof Uint8Array
    ? JSON.parse(Buffer.from(rawBody).toString('utf8')) as unknown
    : rawBody;
  if (!isPlainObject(value)) {
    throw new Error('webhook event envelope must be an object');
  }
  if (typeof value.id !== 'string' || value.id.length === 0) {
    throw new Error('webhook event id is required');
  }
  if (value.object !== 'webhook_event') {
    throw new Error('webhook event object must be webhook_event');
  }
  if (typeof value.type !== 'string' || value.type.length === 0) {
    throw new Error('webhook event type is required');
  }
  if (typeof value.created !== 'string' || value.created.length === 0) {
    throw new Error('webhook event created timestamp is required');
  }
  if (!isPlainObject(value.data)) {
    throw new Error('webhook event data must be an object');
  }
  const data = value.type === 'gate.session.approved'
    ? validateGateApprovedWebhookPayload(value.data)
    : value.data;
  return {
    id: value.id,
    object: 'webhook_event',
    type: value.type as WebhookEventEnvelope['type'],
    created: value.created,
    data,
  };
}

export function verifyAndParseWebhookEvent(input: VerifyAndParseWebhookEventInput): WebhookEventEnvelope {
  if (!verifyGateWebhookSignature(input)) {
    throw new Error('Invalid Tripwire webhook signature');
  }
  return parseWebhookEvent(input.rawBody);
}

export function encryptGateDeliveryPayload(
  delivery: GateDeliveryRequest,
  payload: GateDeliveryPayload,
): GateDeliveryEnvelope {
  const validatedDelivery = validateGateDeliveryRequest(delivery);
  if (payload.version !== GATE_DELIVERY_VERSION) {
    throw new Error('Gate delivery payload version must be 1');
  }
  const { publicKey: ephemeralPublicKey, privateKey: ephemeralPrivateKey } = generateKeyPairSync('x25519');
  const recipientPublicKey = createPublicKeyFromRawX25519(
    fromBase64Url(validatedDelivery.public_key, 'delivery.public_key'),
  );
  const sharedSecret = diffieHellman({
    privateKey: ephemeralPrivateKey,
    publicKey: recipientPublicKey,
  });
  const salt = randomBytes(32);
  const iv = randomBytes(12);
  const aeadKey = new Uint8Array(hkdfSync('sha256', sharedSecret, salt, GATE_DELIVERY_HKDF_INFO, 32));
  const cipher = createCipheriv('aes-256-gcm', aeadKey, iv);
  const ciphertext = Buffer.concat([
    cipher.update(JSON.stringify(payload), 'utf8'),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();
  return {
    version: GATE_DELIVERY_VERSION,
    algorithm: GATE_DELIVERY_ALGORITHM,
    key_id: validatedDelivery.key_id,
    ephemeral_public_key: toBase64Url(rawX25519PublicKeyFromKeyObject(ephemeralPublicKey)),
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
    tag: toBase64Url(tag),
  };
}

export function validateEncryptedGateDeliveryEnvelope(value: unknown): GateDeliveryEnvelope {
  if (!value || typeof value !== 'object') {
    throw new Error('encrypted delivery must be an object');
  }
  const candidate = value as Record<string, unknown>;
  if (candidate.version !== GATE_DELIVERY_VERSION) {
    throw new Error('encrypted_delivery.version must be 1');
  }
  if (candidate.algorithm !== GATE_DELIVERY_ALGORITHM) {
    throw new Error(`encrypted_delivery.algorithm must be ${GATE_DELIVERY_ALGORITHM}`);
  }
  for (const field of ['key_id', 'ephemeral_public_key', 'salt', 'iv', 'ciphertext', 'tag'] as const) {
    if (typeof candidate[field] !== 'string' || candidate[field].length === 0) {
      throw new Error(`encrypted_delivery.${field} is required`);
    }
  }
  if (fromBase64Url(candidate.ephemeral_public_key as string, 'encrypted_delivery.ephemeral_public_key').length !== 32) {
    throw new Error('encrypted_delivery.ephemeral_public_key must be 32 bytes');
  }
  if (fromBase64Url(candidate.salt as string, 'encrypted_delivery.salt').length !== 32) {
    throw new Error('encrypted_delivery.salt must be 32 bytes');
  }
  if (fromBase64Url(candidate.iv as string, 'encrypted_delivery.iv').length !== 12) {
    throw new Error('encrypted_delivery.iv must be 12 bytes');
  }
  if (fromBase64Url(candidate.tag as string, 'encrypted_delivery.tag').length !== 16) {
    throw new Error('encrypted_delivery.tag must be 16 bytes');
  }
  return candidate as unknown as GateDeliveryEnvelope;
}

export function decryptGateDeliveryEnvelope(
  privateKey: KeyObject,
  envelope: GateDeliveryEnvelope,
): GateDeliveryPayload {
  const validated = validateEncryptedGateDeliveryEnvelope(envelope);
  const ephemeralPublicKey = createPublicKeyFromRawX25519(
    fromBase64Url(validated.ephemeral_public_key, 'encrypted_delivery.ephemeral_public_key'),
  );
  const sharedSecret = diffieHellman({
    privateKey,
    publicKey: ephemeralPublicKey,
  });
  const aeadKey = new Uint8Array(hkdfSync(
    'sha256',
    sharedSecret,
    fromBase64Url(validated.salt, 'encrypted_delivery.salt'),
    GATE_DELIVERY_HKDF_INFO,
    32,
  ));
  const decipher = createDecipheriv('aes-256-gcm', aeadKey, fromBase64Url(validated.iv, 'encrypted_delivery.iv'));
  decipher.setAuthTag(fromBase64Url(validated.tag, 'encrypted_delivery.tag'));
  const plaintext = Buffer.concat([
    decipher.update(fromBase64Url(validated.ciphertext, 'encrypted_delivery.ciphertext')),
    decipher.final(),
  ]).toString('utf8');
  let parsed: unknown;
  try {
    parsed = JSON.parse(plaintext);
  } catch {
    throw new Error('encrypted_delivery decrypted to invalid JSON');
  }
  if (!parsed || typeof parsed !== 'object') {
    throw new Error('encrypted_delivery payload must be an object');
  }
  const candidate = parsed as Record<string, unknown>;
  if (candidate.version !== GATE_DELIVERY_VERSION) {
    throw new Error('encrypted_delivery payload version must be 1');
  }
  if (!candidate.outputs || typeof candidate.outputs !== 'object' || Array.isArray(candidate.outputs)) {
    throw new Error('encrypted_delivery payload outputs must be an object');
  }
  const outputs: Record<string, string> = {};
  for (const [key, value] of Object.entries(candidate.outputs as Record<string, unknown>)) {
    if (typeof value !== 'string') {
      throw new Error(`encrypted_delivery output ${key} must be a string`);
    }
    outputs[key] = value;
  }
  const ackToken = typeof candidate.ack_token === 'string' ? candidate.ack_token : undefined;
  return {
    version: GATE_DELIVERY_VERSION,
    outputs,
    ...(ackToken ? { ack_token: ackToken } : {}),
  };
}
