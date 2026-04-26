# Tripwire Node Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Node 18+](https://img.shields.io/badge/node-%E2%89%A518-339933?logo=node.js&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Tripwire Node library provides convenient access to the Tripwire API from applications running in Node.js. It includes a typed client for Sessions, Fingerprints, Organizations, organization API key management, sealed token verification, Gate, and Gate delivery/webhook helpers.

The library also provides:

- a fast configuration path using `TRIPWIRE_SECRET_KEY`
- helpers for cursor-based pagination
- structured API errors and built-in sealed token verification
- webhook endpoint management, test sends, and event delivery history
- public, bearer-token, and secret-key auth modes for Gate flows
- Gate delivery/webhook helpers

## Documentation

See the [Tripwire docs](https://tripwirejs.com/docs) and [API reference](https://tripwirejs.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the package. If you just want to use the package, run:

```bash
npm install @abxy/tripwire-server
```

## Requirements

- Node 18+

## Usage

Use `TRIPWIRE_SECRET_KEY` or an explicit `secretKey` for core detect APIs. For public or bearer-auth Gate flows, the client can also be constructed without a secret key:

```ts
import { Tripwire } from "@abxy/tripwire-server";

const client = new Tripwire({
  secretKey: process.env.TRIPWIRE_SECRET_KEY,
});

const page = await client.sessions.list({ verdict: "bot", limit: 25 });
const session = await client.sessions.get("sid_123");

console.log(page.has_more, page.next_cursor);
console.log(session.decision.risk_score, session.highlights[0]?.summary);
```

### Sealed token verification

```ts
import { safeVerifyTripwireToken } from "@abxy/tripwire-server";

const result = safeVerifyTripwireToken(
  sealedToken,
  process.env.TRIPWIRE_SECRET_KEY,
);

if (!result.ok) {
  console.error(result.error);
  return;
}

console.log(result.data.decision.verdict, result.data.decision.risk_score);
```

### Pagination

```ts
for await (const session of client.sessions.iter({ search: "signup" })) {
  console.log(session.id, session.latest_decision.verdict);
}
```

### Fingerprints

```ts
const page = await client.fingerprints.list({ sort: "seen_count" });
const fingerprint = await client.fingerprints.get("vid_123");

console.log(fingerprint.lifecycle.last_seen_at);
```

### Organizations

```ts
const organization = await client.organizations.get("org_123");
const updated = await client.organizations.update("org_123", { name: "New Name" });
```

### Organization API keys

```ts
const created = await client.organizations.apiKeys.create("org_123", {
  name: "Production",
  type: "secret",
  environment: "live",
  scopes: ["sessions:list", "sessions:read"],
});

await client.organizations.apiKeys.revoke("org_123", created.id);
```

### Webhooks

```ts
const endpoint = await client.webhooks.createEndpoint("org_123", {
  name: "Production alerts",
  url: "https://example.com/tripwire/webhook",
  event_types: ["session.result.persisted", "gate.session.approved"],
});

const events = await client.webhooks.listEvents("org_123", {
  endpoint_id: endpoint.id,
  type: "session.result.persisted",
});

console.log(events.items[0]?.webhook_deliveries[0]?.status);
```

### Gate APIs

```ts
const client = new Tripwire();

const services = await client.gate.registry.list();
const session = await client.gate.sessions.create({
  service_id: "tripwire",
  account_name: "my-project",
  delivery: createDeliveryKeyPair().delivery,
});

console.log(services[0]?.id, session.consent_url);
```

### Gate delivery and webhook helpers

```ts
import {
  createDeliveryKeyPair,
  createGateApprovedWebhookResponse,
  decryptGateDeliveryEnvelope,
  verifyGateWebhookSignature,
} from "@abxy/tripwire-server";

const keyPair = createDeliveryKeyPair();
const response = createGateApprovedWebhookResponse({
  delivery: keyPair.delivery,
  outputs: {
    TRIPWIRE_PUBLISHABLE_KEY: "pk_live_...",
    TRIPWIRE_SECRET_KEY: "sk_live_...",
  },
});

const payload = decryptGateDeliveryEnvelope(keyPair.privateKey, response.encrypted_delivery);
console.log(payload.outputs.TRIPWIRE_SECRET_KEY);

console.log(verifyGateWebhookSignature({
  secret: "whsec_test",
  timestamp: "1735776000",
  rawBody: "{\"event\":\"gate.session.approved\"}",
  signature: "…",
}));
```

### Error handling

```ts
import { TripwireApiError } from "@abxy/tripwire-server";

try {
  await client.sessions.list({ limit: 999 });
} catch (error) {
  if (error instanceof TripwireApiError) {
    console.error(error.status, error.code, error.message);
  }
}
```

## Support

If you need help integrating Tripwire, start with [tripwirejs.com/docs](https://tripwirejs.com/docs).
