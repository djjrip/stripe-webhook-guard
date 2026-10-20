# Stripe Webhook Guard

> **Experimental Node.js/TypeScript helper and source-pattern checker. Not a production-security certification.**

This repository contains two small tools:

1. A webhook helper that verifies a supplied Stripe signature and delegates event deduplication to an `IdempotencyStore`.
2. A source-pattern scanner that flags selected implementation smells in webhook-related JavaScript/TypeScript files.

The goal is to make a few common mistakes easier to notice. It is not a penetration test, complete static-analysis engine, compliance tool, or proof that an application is safe.

## Current limitations

- The built-in `MemoryIdempotencyStore` is process-local. Records disappear on restart and are not shared across server instances. It is only suitable for local experiments/tests.
- No durable SQL/Redis idempotency adapter is included in this repository.
- The helper cannot guarantee exactly-once business effects, zero loss, or zero duplicate fulfillment. Production behavior depends on your route, storage adapter, transaction boundaries, downstream side effects, retries, and operational design.
- The scanner uses source-pattern/regular-expression heuristics. It is **not an AST analyzer** and can produce false positives and false negatives.
- A clean scan or passing synthetic tests does not establish production readiness.
- No security certification, compliance status, or independent performance benchmark is claimed.

## Requirements and local checks

Use a supported Node.js version and npm.

```bash
npm ci
npm run build
npm test
node bin/cli.js verify
node bin/cli.js audit ./src
```

The tests exercise synthetic events and fixtures, including valid/invalid signature handling, duplicate suppression within the in-memory store, handler retry behavior, and selected source-pattern rules. These are regression checks for this repository—not proof of secure behavior in a customer's deployment.

## Signature verification

For a real Stripe endpoint:

- Use the exact raw request body bytes received by the server.
- Read the `Stripe-Signature` header.
- Load the endpoint signing secret from a protected environment/secret manager.
- Reject requests when the header or signing secret is absent or invalid.
- Do not parse and re-serialize request JSON before signature verification.
- Never log or commit signing secrets or customer payloads unnecessarily.

This helper's `processEvent` now fails closed when its configured signing secret or the signature header is missing. It is still the integrating application's responsibility to pass the correct raw body, configure the correct endpoint secret, implement error behavior, and validate the end-to-end route.

## Idempotency and failure recovery

The included `MemoryIdempotencyStore` supports local behavior checks only. It is not a durable or distributed lock. A production implementation requires a persistence layer that safely coordinates concurrent deliveries and survives process restarts. It also needs an explicit business-level strategy for retries, partial side effects, and dead-letter/manual reconciliation.

Before production use, implement and test a durable adapter, including concurrent duplicate delivery, process restart, handler failure after partial work, transaction conflicts, retry exhaustion, and manual recovery.

## Source-pattern checks

The scanner currently checks selected patterns such as:

- Common Express JSON parsing patterns that may discard the original request body.
- Webhook-like route handlers with no obvious signature-verification invocation.
- Some event-id/idempotency hints.
- Selected synchronous-work patterns.
- Obvious webhook-secret literals.
- A heuristic for Next.js App Router POST handlers that call `request.json()` without an obvious raw-body read.

These rules only inspect source text. They do not establish control flow, runtime behavior, whether a referenced function verifies correctly, whether a storage adapter is durable, or whether an apparent issue is exploitable. Review each finding manually and test the real route.

## Async-first review workflow

For an initial written review, a customer can provide:

1. A small, redacted route example and relevant middleware/configuration.
2. The framework and runtime/version.
3. A description of the expected success/failure behavior.
4. Redacted test output or reproducible symptoms.
5. Written acceptance criteria.

Do not send secrets, live webhook signing keys, customer payloads, production database credentials, identity data, or private repositories to an unapproved external service. A review begins only after scope, access, handling of sensitive data, deliverables, and acceptance criteria are agreed in writing. A synchronous call is not required for an initial inquiry.

## Status and commercial claims

This project is experimental. There is no bundled durable idempotency database, production SLA, compliance certification, guaranteed turnaround time, or proof of deployment on customer systems. Any paid assistance must have a separate, written scope with explicit exclusions and acceptance criteria. A public checkout or passing local test is not evidence that a paid service has been delivered.

## License

MIT. See [LICENSE](LICENSE).
