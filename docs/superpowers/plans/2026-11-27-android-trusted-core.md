# Android Trusted Core Implementation Plan

> **For agentic workers:** Use superpowers:executing-plans or superpowers:subagent-driven-development. Every behavior change starts with a failing JVM/Android test.

**Goal:** Make Android subscription fetching DNS-pinned and bounded, authenticate source manifests, encrypt imported credentials, and make VPN start/stop/testing/network changes cancellation-safe.

**Architecture:** Keep AndroidLibXrayLite and the existing UI, add small trust-boundary modules, and route all network/storage/lifecycle operations through them. Unsafe legacy paths are removed rather than retained as fallback.

**Tech Stack:** Java 8, Android API 24+, JVM test harnesses, Android Keystore AES/GCM, RSA/SHA-256 source manifests, ExecutorService cancellation tokens.

**Spec:** `docs/superpowers/specs/2026-11-27-hardening-v4-design.md`

## Global Constraints

- No node URI, subscription token, password, or private signing key in git or logs.
- No silent fallback to an unpinned downloader, unsigned remote manifest, plaintext credential store, or uncancelled start path.
- Unknown ownership/evidence never authorizes a state transition.
- Keep public APK node assets empty.
- Do not modify the running `Desktop/代理便携版`.
- Real-device VPN, DNS/IPv6/WebRTC, network-switch, and Keystore behaviour require explicit manual acceptance.

## Implementation Status (2026-11-27)

- Task 1 is implemented: `ValidatedHttp` performs one validated DNS lookup per hop, pins the socket to that IP, preserves Host/SNI and endpoint-identification, enforces HTTPS in production, limits redirects/bytes, and supports cancellation. Both legacy `HttpURLConnection` fetch paths are removed.
- JVM verification passes 46 URL/address guard cases and 14 transport cases, including real TLS success for the correct hostname and failure for a wrong hostname. Full Android javac against the fixed Xray AAR passes (22 classes).
- Task 2 is implemented: `sources.json` is versioned and signed as exact bytes with RSA/SHA-256; the APK embeds the public key, manifest, and raw signature. Remote mirrors are accepted only after signature/schema validation and a strictly newer version; failures fall back to the signed APK asset and then the compiled snapshot.
- Repository verification passes 9 Python signature/embedding tests (including 4 tool-free verifier controls) and 9 JVM tamper/replay/schema tests. A real debug APK was built and its embedded manifest/signature bytes were extracted and re-verified successfully.
- Task 3 is implemented at the code/compile level: `SecureEnvelope` provides versioned AES-256-GCM encryption with random IV and key-bound AAD; `SecureStore` wraps Android Keystore, migrates legacy plaintext only after durable encrypted persistence, and never writes new plaintext. Seven JVM envelope controls pass; all 13 Android sources compile against API 35 and the fixed AAR.
- Tasks 4–5 remain in progress. Real Android Keystore generation/migration, VPN lifecycle, network switching, DNS/IPv6/WebRTC leaks, and battery behaviour are not yet device-verified.

## Tasks

1. **Validated HTTP and DNS pinning**
   - Create `phone/src/com/luhui/phoneproxy/ValidatedHttp.java`.
   - Extend `SubscriptionGuard` with single-resolution address validation.
   - Replace both `HttpURLConnection` fetch paths in `ConfigBuilder`.
   - JVM tests cover one resolution, mixed private answers, Host preservation, redirects, downgrade, chunked bodies, byte limits, HTTP errors, loops, and cancellation.

2. **Signed source manifests**
   - Version and sign `phone/sources.json`; embed the public key in `SourceManifest.java`.
   - Add `tools/sign_sources.py` and `tools/verify_sources.py`.
   - Remote mirrors provide availability only; invalid/missing/old signatures fall back to the APK built-in signed list.
   - Tests cover missing signature, tampering, replay, malformed schema, and valid signature.

3. **Encrypted credential storage**
   - Create `SecureStore.java` using Android Keystore AES/GCM.
   - Migrate legacy imported URIs, delete plaintext only after encrypted persistence succeeds, and route all reads/writes through the store.
   - JVM tests cover the pure envelope codec; CI compiles the Android wrapper. Real Keystore migration remains a device test.

4. **Cancellation and lifecycle**
   - Add a shared cancellation token to `NodeTester`; shutdown and reap pools before completion callbacks.
   - Add service session generations and a stop flag so stale start/maintenance work cannot create a VPN after STOP.
   - Debounce network loss/capability changes, invalidate stale health, and rebuild/rebind safely.
   - Add core-death detection and bounded recovery; preserve kill-switch/always-on guidance.
   - Tests cover stop-before-start, stale generation, cancellation callbacks, executor reaping, and network debounce decisions.

5. **Verification and documentation**
   - Run JVM proofs, Android javac/build, poison corpus, release guards, policy sync, and the full PC regression.
   - Update design/status and release documentation with verified and unverified items.
   - Commit each task separately; push only after the complete branch is green.
