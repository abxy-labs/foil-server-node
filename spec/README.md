# Server SDK Spec

This directory is the authoritative cross-language contract for Tripwire server SDKs.

It defines:

- the supported server API surface
- the shared sealed token verification behavior
- the shared Gate delivery/webhook helper behavior
- golden fixtures for success, error, pagination, and helper flows

## Scope

Server SDKs include only customer-facing APIs:

- `/v1/sessions`
- `/v1/fingerprints`
- `/v1/organizations`
- `/v1/organizations/:organizationId/api-keys`
- `/v1/gate/registry`
- `/v1/gate/services`
- `/v1/gate/sessions`
- `/v1/gate/login-sessions`
- `/v1/gate/agent-tokens/*`

Server SDKs do **not** include:

- collect endpoints
- internal scoring APIs
- dashboard/internal APIs
- framework adapters
- retry middleware
- policy helpers like `shouldBlock`

## Required Namespaces

Every server SDK should expose these top-level capabilities:

- Sessions
  - list
  - get
  - iterator / auto-pagination helper
- Fingerprints
  - list
  - get
  - iterator / auto-pagination helper
- Organizations
  - create
  - get
  - update
- Organization API keys
  - create
  - list
  - revoke
  - rotate
- Gate
  - registry list/get
  - services list/get/create/update/disable
  - sessions create/poll/acknowledge
  - login sessions create/consume
  - agent tokens verify/revoke
- sealed token helpers
  - strict verify
  - safe verify
- Gate delivery/webhook helpers
  - generate delivery keypair
  - import/export delivery private key
  - validate delivery request
  - encrypt/decrypt delivery envelopes
  - validate approved webhook payload
  - verify webhook signature
  - derive agent-token env keys
  - check blocked/managed Gate env vars

## Shared Defaults

Every SDK should default to:

- `base_url = https://api.tripwirejs.com`
- `secret_key = env(TRIPWIRE_SECRET_KEY)`
- support for public, bearer-token, and secret-key auth as required by the Gate surface
- request timeout support
- no automatic retries

## Pagination Normalization

List APIs should normalize cursor pagination into these fields using each language's native style:

- `items`
- `limit`
- `has_more`
- `next_cursor`

The underlying API responses remain cursor-based. SDKs may expose helper iterators/enumerators/page walkers on top.

## Error Model

SDKs should parse API failures into structured errors with, at minimum:

- `status`
- `code`
- `message`
- `request_id`
- `field_errors`
- `docs_url`
- parsed raw body

Use the fixtures in `fixtures/errors/` as the source of truth for error-shape behavior.

## Sealed Token Verification

`sealed-token.md` is the cross-language source of truth for verification behavior.

SDKs must implement verification natively in their own language runtime. They should not depend on another SDK implementation.

Use both:

- `fixtures/sealed-token/vector.v1.json`
- `fixtures/sealed-token/invalid.json`

to validate correctness and failure behavior.

## Gate Delivery Helper Coverage

Use the shared fixtures in `fixtures/gate-delivery/` to validate:

- delivery request validation and key-id derivation
- envelope encrypt/decrypt roundtrips
- approved webhook payload validation
- webhook signature verification
- Gate env-var policy helpers

## Sync Model

This repo is the source of truth for the shared server SDK contract.

Each language SDK repo carries a synced copy of this repository in `spec/`, and the Tripwire monorepo vendors this repository as a submodule at `sdk-spec/server`.

Keep the synced copies and the monorepo submodule pointer current before advancing them.

## SDK Authoring Checklist

When changing any server SDK:

- sync `spec/` before changing SDK code or tests
- do not expose collect or internal-only endpoints
- preserve the shared defaults:
  - env-based secret key fallback
  - `https://api.tripwirejs.com`
  - request timeout support
  - no automatic retries
- preserve pagination normalization:
  - `items`
  - `limit`
  - `has_more`
  - `next_cursor`
- preserve structured API errors
- keep sealed token golden-vector coverage
- keep one live smoke suite per SDK
- only update the vendored SDK `spec/` copies or the monorepo submodule pointer after the relevant CI is green
