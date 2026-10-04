import { describe, expect, it } from 'vitest';
import {
  parseWebhookEvent,
  verifyAndParseWebhookEvent,
  verifyWebhookSignature,
} from '../src/webhooks';
import { loadFixture } from './helpers';

interface WebhookSignatureFixture {
  secret: string;
  timestamp: string;
  expired_timestamp: string;
  now_seconds: number;
  raw_body: string;
  signature: string;
  invalid_signature: string;
}

const fixture = loadFixture<WebhookSignatureFixture>('webhooks/signature.json');

function verifyInput(overrides: Partial<Parameters<typeof verifyWebhookSignature>[0]> = {}) {
  return {
    secret: fixture.secret,
    timestamp: fixture.timestamp,
    rawBody: fixture.raw_body,
    signature: fixture.signature,
    nowSeconds: fixture.now_seconds,
    ...overrides,
  };
}

describe('webhook helpers', () => {
  it('verifies a valid signature', () => {
    expect(verifyWebhookSignature(verifyInput())).toBe(true);
  });

  it('rejects a tampered signature, body, or secret', () => {
    expect(verifyWebhookSignature(verifyInput({ signature: fixture.invalid_signature }))).toBe(false);
    expect(verifyWebhookSignature(verifyInput({ signature: 'short' }))).toBe(false);
    expect(verifyWebhookSignature(verifyInput({ rawBody: `${fixture.raw_body} ` }))).toBe(false);
    expect(verifyWebhookSignature(verifyInput({ secret: 'whsec_other' }))).toBe(false);
  });

  it('rejects expired and malformed timestamps', () => {
    expect(verifyWebhookSignature(verifyInput({ timestamp: fixture.expired_timestamp }))).toBe(false);
    expect(verifyWebhookSignature(verifyInput({ timestamp: 'not-a-timestamp' }))).toBe(false);
  });

  it('honors a custom max age', () => {
    expect(verifyWebhookSignature(verifyInput({
      nowSeconds: fixture.now_seconds + 600,
      maxAgeSeconds: 900,
    }))).toBe(true);
  });

  it('parses session.result.persisted events', () => {
    expect(parseWebhookEvent(fixture.raw_body)).toMatchObject({
      id: 'wevt_0123456789abcdef0123456789abcdef',
      object: 'webhook_event',
      type: 'session.result.persisted',
      created: '2026-01-02T00:00:00.000Z',
      data: { object: 'session_result', session: { id: 'sid_0123456789abcdefghjkmnpqrs' } },
    });
    expect(parseWebhookEvent(Buffer.from(fixture.raw_body, 'utf8')).type).toBe('session.result.persisted');
    expect(parseWebhookEvent(JSON.parse(fixture.raw_body)).type).toBe('session.result.persisted');
  });

  it('parses webhook.test events', () => {
    expect(parseWebhookEvent(JSON.stringify({
      id: 'wevt_0123456789abcdefghjkmnpqrs',
      object: 'webhook_event',
      type: 'webhook.test',
      created: '2026-04-27T00:00:00.000Z',
      data: {},
    })).type).toBe('webhook.test');
  });

  it('rejects unsupported or malformed events', () => {
    const base = {
      id: 'wevt_0123456789abcdefghjkmnpqrs',
      object: 'webhook_event',
      type: 'session.result.persisted',
      created: '2026-04-27T00:00:00.000Z',
      data: {},
    };
    expect(() => parseWebhookEvent(JSON.stringify({ ...base, type: 'unknown.event' }))).toThrow(/unsupported webhook event type/);
    expect(() => parseWebhookEvent(JSON.stringify({ ...base, object: 'event' }))).toThrow(/webhook_event/);
    expect(() => parseWebhookEvent(JSON.stringify({ ...base, data: [] }))).toThrow(/data must be an object/);
    expect(() => parseWebhookEvent(JSON.stringify([base]))).toThrow(/must be an object/);
  });

  it('verifies the signature before parsing', () => {
    expect(verifyAndParseWebhookEvent(verifyInput())).toMatchObject({
      type: 'session.result.persisted',
    });
    expect(() => verifyAndParseWebhookEvent(verifyInput({ signature: fixture.invalid_signature })))
      .toThrow(/Invalid Foil webhook signature/);
  });
});
