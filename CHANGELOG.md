# Changelog

All notable changes to **Stripe Webhook Guard** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-08-17

### Added
- Core `StripeWebhookGuard` dispatcher with event routing (`guard.on('checkout.session.completed', handler)`).
- Strict cryptographic HMAC SHA256 signature verification and timestamp drift validation (5-minute window).
- Pluggable `IdempotencyStore` architecture with zero-allocation `MemoryIdempotencyStore` implementation.
- Automated duplicate event suppression returning fast `200 OK (DUPLICATE_IGNORED)` to prevent double charging.
- Full TypeScript typings (`dist/src/index.d.ts`), runnable Express examples, and automated unit test suite.
- Enterprise support & custom payment integration funnel for GG Loop LLC.
