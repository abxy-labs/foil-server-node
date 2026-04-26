import { describe, expect, it } from 'vitest';
import {
  createDeliveryKeyPair,
  createGateApprovedWebhookResponse,
  decryptGateDeliveryEnvelope,
  deriveGateAgentTokenEnvKey,
  importDeliveryPrivateKeyPkcs8,
  isBlockedGateEnvVarKey,
  isGateManagedEnvVarKey,
  parseWebhookEvent,
  validateGateApprovedWebhookPayload,
  validateGateDeliveryRequest,
  verifyAndParseWebhookEvent,
  verifyGateWebhookSignature,
} from '../src/gate-delivery';
import { loadFixture } from './helpers';

interface GateDeliveryVectorFixture {
  delivery: {
    version: 1;
    algorithm: 'x25519-hkdf-sha256/aes-256-gcm';
    key_id: string;
    public_key: string;
  };
  private_key_pkcs8: string;
  payload: {
    version: 1;
    outputs: Record<string, string>;
    ack_token?: string;
  };
  envelope: {
    version: 1;
    algorithm: 'x25519-hkdf-sha256/aes-256-gcm';
    key_id: string;
    ephemeral_public_key: string;
    salt: string;
    iv: string;
    ciphertext: string;
    tag: string;
  };
}

describe('gate delivery helpers', () => {
  it('validates the shared delivery request fixture and decrypts the shared vector', () => {
    const deliveryRequestFixture = loadFixture<{
      delivery: GateDeliveryVectorFixture['delivery'];
      derived_key_id: string;
    }>('gate-delivery/delivery-request.json');
    const vectorFixture = loadFixture<GateDeliveryVectorFixture>('gate-delivery/vector.v1.json');

    expect(validateGateDeliveryRequest(deliveryRequestFixture.delivery)).toEqual(deliveryRequestFixture.delivery);
    expect(deliveryRequestFixture.delivery.key_id).toBe(deliveryRequestFixture.derived_key_id);

    const privateKey = importDeliveryPrivateKeyPkcs8(vectorFixture.private_key_pkcs8);
    expect(decryptGateDeliveryEnvelope(privateKey, vectorFixture.envelope)).toEqual(vectorFixture.payload);
  });

  it('validates approved webhook payloads and signature fixtures', () => {
    const payloadFixture = loadFixture<Record<string, unknown>>('gate-delivery/approved-webhook-payload.valid.json');
    const signatureFixture = loadFixture<{
      secret: string;
      timestamp: string;
      expired_timestamp: string;
      now_seconds: number;
      raw_body: string;
      signature: string;
      invalid_signature: string;
    }>('gate-delivery/webhook-signature.json');

    expect(validateGateApprovedWebhookPayload(payloadFixture)).toEqual(payloadFixture);
    expect(parseWebhookEvent(signatureFixture.raw_body)).toMatchObject({
      object: 'webhook_event',
      type: 'gate.session.approved',
      data: {
        service_id: payloadFixture.service_id,
        gate_session_id: payloadFixture.gate_session_id,
      },
    });
    expect(verifyAndParseWebhookEvent({
      secret: signatureFixture.secret,
      timestamp: signatureFixture.timestamp,
      rawBody: signatureFixture.raw_body,
      signature: signatureFixture.signature,
      nowSeconds: signatureFixture.now_seconds,
    })).toMatchObject({
      type: 'gate.session.approved',
    });
    expect(verifyGateWebhookSignature({
      secret: signatureFixture.secret,
      timestamp: signatureFixture.timestamp,
      rawBody: signatureFixture.raw_body,
      signature: signatureFixture.signature,
      nowSeconds: signatureFixture.now_seconds,
    })).toBe(true);
    expect(verifyGateWebhookSignature({
      secret: signatureFixture.secret,
      timestamp: signatureFixture.timestamp,
      rawBody: signatureFixture.raw_body,
      signature: signatureFixture.invalid_signature,
      nowSeconds: signatureFixture.now_seconds,
    })).toBe(false);
    expect(verifyGateWebhookSignature({
      secret: signatureFixture.secret,
      timestamp: signatureFixture.expired_timestamp,
      rawBody: signatureFixture.raw_body,
      signature: signatureFixture.signature,
      nowSeconds: signatureFixture.now_seconds,
    })).toBe(false);
  });

  it('exposes env-policy helpers from the shared fixtures', () => {
    const fixture = loadFixture<{
      derive_agent_token_env_key: Array<{ service_id: string; expected: string }>;
      is_gate_managed_env_var_key: Array<{ key: string; managed: boolean }>;
      is_blocked_gate_env_var_key: Array<{ key: string; blocked: boolean }>;
    }>('gate-delivery/env-policy.json');

    for (const entry of fixture.derive_agent_token_env_key) {
      expect(deriveGateAgentTokenEnvKey(entry.service_id)).toBe(entry.expected);
    }
    for (const entry of fixture.is_gate_managed_env_var_key) {
      expect(isGateManagedEnvVarKey(entry.key)).toBe(entry.managed);
    }
    for (const entry of fixture.is_blocked_gate_env_var_key) {
      expect(isBlockedGateEnvVarKey(entry.key)).toBe(entry.blocked);
    }
  });

  it('creates encrypted delivery responses that roundtrip against generated keys', () => {
    const keyPair = createDeliveryKeyPair();
    const response = createGateApprovedWebhookResponse({
      delivery: keyPair.delivery,
      outputs: {
        TRIPWIRE_PUBLISHABLE_KEY: 'pk_live_bundle',
        TRIPWIRE_SECRET_KEY: 'sk_live_bundle',
      },
    });

    expect(decryptGateDeliveryEnvelope(keyPair.privateKey, response.encrypted_delivery)).toEqual({
      version: 1,
      outputs: {
        TRIPWIRE_PUBLISHABLE_KEY: 'pk_live_bundle',
        TRIPWIRE_SECRET_KEY: 'sk_live_bundle',
      },
    });
  });
});
