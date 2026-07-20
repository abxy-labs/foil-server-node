import { createDecipheriv, createHash, timingSafeEqual } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { FoilConfigurationError, FoilTokenVerificationError } from './errors';
import type { SafeVerifyFoilTokenResult, VerifiedFoilToken } from './types';

const LEGACY_VERSION = 0x01;
const MULTI_RECIPIENT_VERSION = 0x02;
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
const CONTENT_KEY_BYTES = 32;
const RECIPIENT_ID_BYTES = 32;
const MAX_RECIPIENTS = 256;
const V2_HEADER_BYTES = 1 + 2 + NONCE_BYTES + 4;
const V2_RECIPIENT_BYTES = RECIPIENT_ID_BYTES + NONCE_BYTES + CONTENT_KEY_BYTES + TAG_BYTES;
const V2_PAYLOAD_AAD_PREFIX = Buffer.from('foil-sealed-results-v2\0payload\0', 'utf8');
const V2_WRAP_AAD_PREFIX = Buffer.from('foil-sealed-results-v2\0recipient\0', 'utf8');

function normalizeSecretMaterial(secretKeyOrHash: string): string {
  return /^[0-9a-f]{64}$/i.test(secretKeyOrHash)
    ? secretKeyOrHash.toLowerCase()
    : createHash('sha256').update(secretKeyOrHash).digest('hex');
}

function deriveKey(secretKeyOrHash: string): Buffer {
  return createHash('sha256')
    .update(`${normalizeSecretMaterial(secretKeyOrHash)}\0sealed-results`)
    .digest();
}

function recipientId(secretKeyOrHash: string): Buffer {
  return createHash('sha256')
    .update(`${normalizeSecretMaterial(secretKeyOrHash)}\0sealed-results-recipient-id`)
    .digest();
}

function verifyLegacyToken(buffer: Buffer, secretKey: string): VerifiedFoilToken {
  const nonce = buffer.subarray(1, 13);
  const tag = buffer.subarray(buffer.length - TAG_BYTES);
  const ciphertext = buffer.subarray(13, buffer.length - TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', deriveKey(secretKey), nonce);
  decipher.setAuthTag(tag);
  const compressed = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return JSON.parse(inflateSync(compressed).toString('utf8')) as VerifiedFoilToken;
}

function verifyMultiRecipientToken(buffer: Buffer, secretKey: string): VerifiedFoilToken {
  if (buffer.length < V2_HEADER_BYTES + TAG_BYTES + V2_RECIPIENT_BYTES) {
    throw new FoilTokenVerificationError('Foil token is too short.');
  }
  const recipientCount = buffer.readUInt16BE(1);
  if (recipientCount < 1 || recipientCount > MAX_RECIPIENTS) {
    throw new FoilTokenVerificationError('Foil token has an invalid recipient count.');
  }
  const payloadNonce = buffer.subarray(3, 3 + NONCE_BYTES);
  const payloadLength = buffer.readUInt32BE(3 + NONCE_BYTES);
  const payloadStart = V2_HEADER_BYTES;
  const payloadTagStart = payloadStart + payloadLength;
  const recipientsStart = payloadTagStart + TAG_BYTES;
  if (
    payloadLength < 1
    || recipientsStart + (recipientCount * V2_RECIPIENT_BYTES) !== buffer.length
  ) {
    throw new FoilTokenVerificationError('Foil token has an invalid length.');
  }

  const expectedId = recipientId(secretKey);
  const recipientIds = Array.from({ length: recipientCount }, (_, index) => {
    const entryStart = recipientsStart + (index * V2_RECIPIENT_BYTES);
    return buffer.subarray(entryStart, entryStart + RECIPIENT_ID_BYTES);
  });
  let contentKey: Buffer | null = null;
  for (let index = 0; index < recipientCount; index += 1) {
    const entryStart = recipientsStart + (index * V2_RECIPIENT_BYTES);
    const id = buffer.subarray(entryStart, entryStart + RECIPIENT_ID_BYTES);
    if (!timingSafeEqual(id, expectedId)) continue;
    const wrapNonceStart = entryStart + RECIPIENT_ID_BYTES;
    const wrappedKeyStart = wrapNonceStart + NONCE_BYTES;
    const wrapTagStart = wrappedKeyStart + CONTENT_KEY_BYTES;
    const wrapDecipher = createDecipheriv(
      'aes-256-gcm',
      deriveKey(secretKey),
      buffer.subarray(wrapNonceStart, wrappedKeyStart),
    );
    wrapDecipher.setAAD(Buffer.concat([V2_WRAP_AAD_PREFIX, id]));
    wrapDecipher.setAuthTag(buffer.subarray(wrapTagStart, wrapTagStart + TAG_BYTES));
    contentKey = Buffer.concat([
      wrapDecipher.update(buffer.subarray(wrappedKeyStart, wrapTagStart)),
      wrapDecipher.final(),
    ]);
    break;
  }
  if (!contentKey || contentKey.length !== CONTENT_KEY_BYTES) {
    throw new FoilTokenVerificationError('Secret key is not a recipient of this Foil token.');
  }
  const payloadDecipher = createDecipheriv('aes-256-gcm', contentKey, payloadNonce);
  payloadDecipher.setAAD(Buffer.concat([
    V2_PAYLOAD_AAD_PREFIX,
    buffer.subarray(0, V2_HEADER_BYTES),
    ...recipientIds,
  ]));
  payloadDecipher.setAuthTag(buffer.subarray(payloadTagStart, recipientsStart));
  const compressed = Buffer.concat([
    payloadDecipher.update(buffer.subarray(payloadStart, payloadTagStart)),
    payloadDecipher.final(),
  ]);
  return JSON.parse(inflateSync(compressed).toString('utf8')) as VerifiedFoilToken;
}

function resolveSecretKey(secretKey?: string): string {
  const resolved = secretKey ?? process.env.FOIL_SECRET_KEY;
  if (!resolved) {
    throw new FoilConfigurationError(
      'Missing Foil secret key. Pass secretKey explicitly or set FOIL_SECRET_KEY.',
    );
  }
  return resolved;
}

export function verifyFoilToken(
  sealedToken: string,
  secretKey?: string,
): VerifiedFoilToken {
  try {
    const resolvedSecretKey = resolveSecretKey(secretKey);
    const buffer = Buffer.from(sealedToken, 'base64');
    if (buffer.length < 1 + NONCE_BYTES + TAG_BYTES) {
      throw new FoilTokenVerificationError('Foil token is too short.');
    }

    const version = buffer[0];
    if (version !== LEGACY_VERSION && version !== MULTI_RECIPIENT_VERSION) {
      throw new FoilTokenVerificationError(`Unsupported Foil token version: ${version}`);
    }
    return version === LEGACY_VERSION
      ? verifyLegacyToken(buffer, resolvedSecretKey)
      : verifyMultiRecipientToken(buffer, resolvedSecretKey);
  } catch (error) {
    if (error instanceof FoilConfigurationError || error instanceof FoilTokenVerificationError) {
      throw error;
    }
    throw new FoilTokenVerificationError('Failed to verify Foil token.', { cause: error });
  }
}

export function safeVerifyFoilToken(
  sealedToken: string,
  secretKey?: string,
): SafeVerifyFoilTokenResult {
  try {
    return { ok: true, data: verifyFoilToken(sealedToken, secretKey) };
  } catch (error) {
    if (error instanceof FoilConfigurationError || error instanceof FoilTokenVerificationError) {
      return { ok: false, error };
    }
    return {
      ok: false,
      error: new FoilTokenVerificationError('Failed to verify Foil token.', { cause: error }),
    };
  }
}
