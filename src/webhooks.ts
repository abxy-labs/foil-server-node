import { createHmac, timingSafeEqual } from 'node:crypto';
import type { WebhookEventEnvelope } from './types';

const WEBHOOK_EVENT_TYPES = new Set<WebhookEventEnvelope['type']>([
  'session.fingerprint.calculated',
  'session.result.persisted',
  'webhook.test',
]);

export interface VerifyWebhookSignatureInput {
  secret: string;
  timestamp: string;
  rawBody: string;
  signature: string;
  maxAgeSeconds?: number;
  nowSeconds?: number;
}

export interface VerifyAndParseWebhookEventInput extends VerifyWebhookSignatureInput {}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

export function verifyWebhookSignature(input: VerifyWebhookSignatureInput): boolean {
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
  if (!WEBHOOK_EVENT_TYPES.has(value.type as WebhookEventEnvelope['type'])) {
    throw new Error(`unsupported webhook event type: ${value.type}`);
  }
  if (typeof value.created !== 'string' || value.created.length === 0) {
    throw new Error('webhook event created timestamp is required');
  }
  if (!isPlainObject(value.data)) {
    throw new Error('webhook event data must be an object');
  }
  return {
    id: value.id,
    object: 'webhook_event',
    type: value.type as WebhookEventEnvelope['type'],
    created: value.created,
    data: value.data,
  };
}

export function verifyAndParseWebhookEvent(input: VerifyAndParseWebhookEventInput): WebhookEventEnvelope {
  if (!verifyWebhookSignature(input)) {
    throw new Error('Invalid Foil webhook signature');
  }
  return parseWebhookEvent(input.rawBody);
}
