# Foil Node Library

![Preview](https://img.shields.io/badge/status-preview-111827)
![Node 18+](https://img.shields.io/badge/node-%E2%89%A518-339933?logo=node.js&logoColor=white)
![License: MIT](https://img.shields.io/badge/license-MIT-0f766e.svg)

The Foil Node library provides convenient access to the Foil API from applications running in Node.js. It includes a typed client for Sessions, Fingerprints, Organizations, organization API key management, webhook endpoints, and sealed token verification.

The library also provides:

- a fast configuration path using `FOIL_SECRET_KEY`
- helpers for cursor-based pagination
- structured API errors and built-in sealed token verification
- webhook endpoint management, test sends, event delivery history, and webhook signature verification

## Documentation

See the [Foil docs](https://usefoil.com/docs) and [API reference](https://usefoil.com/docs/api-reference/introduction).

## Installation

You don't need this source code unless you want to modify the package. If you just want to use the package, run:

```bash
npm install @abxy/foil-server
```

## Requirements

- Node 18+

## Usage

Use `FOIL_SECRET_KEY` or an explicit `secretKey`:

```ts
import { Foil } from "@abxy/foil-server";

const client = new Foil({
  secretKey: process.env.FOIL_SECRET_KEY,
});

const page = await client.sessions.list({ verdict: "bot", limit: 25 });
const session = await client.sessions.get("sid_123");
await client.sessions.attachClientUser("sid_123", "user_123");
await client.sessions.clearClientUser("sid_123");

console.log(page.has_more, page.next_cursor);
console.log(session.decision.risk_score, session.highlights[0]?.summary);
```

### Sealed token verification

```ts
import { safeVerifyFoilToken } from "@abxy/foil-server";

const result = safeVerifyFoilToken(
  sealedToken,
  process.env.FOIL_SECRET_KEY,
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
  url: "https://example.com/foil/webhook",
  event_types: ["session.result.persisted"],
});

const events = await client.webhooks.listEvents("org_123", {
  endpoint_id: endpoint.id,
  type: "session.result.persisted",
});

console.log(events.items[0]?.webhook_deliveries[0]?.status);
```

#### Verifying webhook deliveries

Every webhook delivery is signed with your endpoint's signing secret. Verify the `X-Foil-Timestamp` and `X-Foil-Signature` headers against the raw request body before trusting the payload:

```ts
import { parseWebhookEvent, verifyAndParseWebhookEvent, verifyWebhookSignature } from "@abxy/foil-server";

const valid = verifyWebhookSignature({
  secret: process.env.FOIL_WEBHOOK_SECRET!,
  timestamp: request.headers["x-foil-timestamp"],
  rawBody,
  signature: request.headers["x-foil-signature"],
});

// Verify and parse in one step. Throws if the signature is invalid or expired.
const event = verifyAndParseWebhookEvent({
  secret: process.env.FOIL_WEBHOOK_SECRET!,
  timestamp: request.headers["x-foil-timestamp"],
  rawBody,
  signature: request.headers["x-foil-signature"],
});

if (event.type === "session.result.persisted") {
  console.log(event.data);
}

// Parse a payload you have already verified.
const parsed = parseWebhookEvent(rawBody);
```

Signatures older than five minutes are rejected by default. Pass `maxAgeSeconds` to change the tolerance.

### Error handling

```ts
import { FoilApiError } from "@abxy/foil-server";

try {
  await client.sessions.list({ limit: 999 });
} catch (error) {
  if (error instanceof FoilApiError) {
    console.error(error.status, error.code, error.message);
  }
}
```

## Support

If you need help integrating Foil, start with [usefoil.com/docs](https://usefoil.com/docs).
