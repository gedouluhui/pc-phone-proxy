# Productization and Release Implementation Plan

> **For agentic workers:** Execute task-by-task with test-first changes and independent review where available.

**Goal:** Deliver a supportable Windows installed product, a modern Android client, and a verifiable release supply chain without weakening the trusted cores.

**Architecture:** Keep sing-box/Xray as data-plane engines. Add a least-privilege Windows broker and shell, resource-driven Android UI, and signed release metadata. Portable mode remains available but cannot register elevated scheduled tasks.

**Tech Stack:** Python/Win32, Inno Setup, Android API 36, Java, GitHub Actions, RSA/SHA-256, CycloneDX/Syft.

**Spec:** `docs/superpowers/specs/2026-11-27-hardening-v4-design.md`

## Global Constraints

- No credentials, private keys, node URIs, subscription tokens, or real diagnostics in git.
- Installed broker lives in `Program Files`; mutable state lives in `%LOCALAPPDATA%\\PhoneProxy`.
- Portable mode never registers elevated tasks. Upgrade/uninstall removes legacy elevated tasks only after action/ACL verification.
- No force push, unsigned release, or silent fallback to an older/unverified artifact.
- Real-device and real-TUN acceptance remains mandatory before release.

## Implementation Status (2026-11-28)

- Windows: verified elevated broker, install manifest/ACL checks, separated `PHONEPROXY_DATA_DIR`, no elevated scheduled-task creation, identity-checked legacy task deletion, tray state/UI, signed update staging, and Inno Setup source are implemented. `runtime/tray.exe` was built and smoke-tested; `dist/PhoneProxy-Setup-4.0.0.exe` was compiled with Inno Setup 7.1.1 and passed the Windows PE/release guard. The updater now has an actual installed-layout regression and bundled `app/release_tools` verification modules.
- Release: CycloneDX 1.6 SBOM, in-toto/SLSA v1 provenance, signed monotonic release manifests, artifact hash verification, pinned Actions and pinned engine downloads are implemented and tested. CI includes the Windows installer guard when an artifact exists.
- Android: target SDK 36, dark palette, accessibility labels/48dp controls, encrypted per-app allowlist, subscription CRUD, search/filter/favorites, and 16 KiB APK alignment checks are implemented. A v4.0.0 public APK was built, signed with the existing test key, verified, aligned, and copied to the desktop package.
- Still open: physical-device VPN/Keystore/network/leak/battery/accessibility acceptance, visible tray GUI and real Windows TUN/UAC/install/upgrade/uninstall acceptance, production APK signing with a non-demo password, Windows Authenticode signing, and legal/telecom/filing/privacy review for a mainland-China commercial service. Offline tests must not be reported as device acceptance.

## Verified Pins (2026-11-28)

- `actions/checkout@v4.2.2` → `11bd71901bbe5b1630ceea73d27597364c9af683`.
- `actions/setup-python@v5.6.0` → `a26af69be951a213d495a4c3e4e4022e16d87065`.
- `actions/setup-java@v4.7.1` → `c5195efecf7bdfc987ee8bae7a71cb8b11521c00`.
- `actions/cache@v4.2.3` → `5a3ec84eff668545956fd18022155c47e93e2684`.
- Observed `libv2ray.aar` v26.11.9 SHA-256: `cdfef146218233a31a8b52c8b1016557730d3b63fc121d4c84cacea50e669155`.
- Observed sing-box 1.14.4 Windows ZIP SHA-256: `99185d75d314a07dbba4a130c8ad986cbeb629a07927975636b341ca61f991df`.

Action SHAs were resolved from upstream tags. Binary hashes are from actual release downloads in this workspace; GitHub API digest metadata was rate-limited, so CI must enforce these observed pins and any future upgrade requires a reviewed hash update.

## Task 1: Windows privileged broker and installation boundary

Files:

- Create `pc/app/broker.py`, `pc/app/install_manifest.py`, `tests_ci/test_broker.py`.
- Modify `pc/_proxy/tun_mode.py` to require broker in installed mode and reject direct elevated script execution.
- Create `pc/installer/PhoneProxy.iss`.

Interfaces:

- `broker.py start|stop|status --data-dir <user dir>` returns JSON without secrets.
- `install_manifest.py verify(<install-dir>) -> bool` checks broker/script hashes and ACL.
- Named commands contain no node credentials; broker reads only its own user data directory.

Tests:

- Wrong install hash/ACL, user-writable broker path, arbitrary data directory, and direct portable elevation are rejected.
- STOP works without START and restores direct connectivity.
- Installer upgrade/uninstall removes only the verified legacy `PhoneProxyTunGuard` action.

## Task 2: Windows tray and signed updater

Files:

- Create `pc/app/tray.py`, `pc/app/updater.py`, `tools/release_manifest.py`.
- Create `tests_ci/test_tray_state.py`, `tests_ci/test_release_manifest.py`.

Interfaces:

- Tray actions: connect, disconnect, split/TUN, diagnose, open logs, exit.
- Updater accepts only a signed `release-manifest.json` with matching filename, size, SHA-256, commit and nondecreasing version.
- Update stages and verifies before launching the installer; failure leaves the current installation untouched.

Tests:

- Wrong signature, hash mismatch, version rollback, path traversal and partial download are rejected.
- Tray state reflects measured service state rather than assuming success.

## Task 3: Android API 36 and accessible product UI

Files:

- Modify `phone/AndroidManifest.xml`, `phone/build_apk.py`, `.github/workflows/ci.yml`.
- Create `phone/res/layout/activity_main.xml`, `phone/res/values/themes.xml`, `phone/res/values-night/themes.xml`, `phone/res/xml/backup_rules.xml` if required by API 36.
- Refactor `MainActivity.java` to resource IDs and state restoration.
- Extend `SecureStore` for subscription URL records.

Interfaces:

- target/compile SDK 36, min SDK 24.
- Node search, protocol filter, favorites, fixed/auto selection and cancel actions.
- Subscription add/update/enable/disable/delete with encrypted URL storage.
- Per-app proxy selection maps to `VpnService.Builder.addAllowedApplication`.
- Diagnostics expose DNS/IPv6/WebRTC checks, kill-switch guidance and redacted log export.

Tests:

- Manifest/aapt2 packaging, orientation and process-death state restoration.
- Accessibility labels, 48dp targets, dynamic text scaling and dark-theme contrast.
- Per-app selection never bypasses domestic/sensitive/AI fail-closed rules.
- Subscription secrets never appear in UI, logs, backups or exported diagnostics.

## Task 4: Release supply chain and provenance

Files:

- Pin every GitHub Action to a reviewed commit SHA and set least-privilege `permissions`.
- Verify sing-box/AAR SHA-256 before extraction; retain Xray/org.json pinned hashes.
- Add Syft/CycloneDX SBOM and SLSA-style provenance generation.
- Extend `phone/check_release.py` and create `pc/check_release.py`.
- Create `.github/workflows/release.yml` as the only publishing path.

Tests:

- Changed binary hash, unpinned action, missing SBOM/provenance, nonempty public node pool, missing signing key, bad zipalign/ELF 16 KiB alignment, and unsigned manifest all fail closed.
- Release artifacts are reproducible from the recorded commit and tool versions.

## Task 5: End-to-end acceptance and handover

- Run all PC/JVM/Android/build/supply-chain checks from a clean checkout.
- Test Windows installed and portable modes, UAC cancel/allow, upgrade/uninstall, update rollback, proxy stop and direct recovery.
- Test Android on at least one arm64 physical device: cold start, import/migration, STOP during start/test, Wi-Fi↔cellular, core death, always-on, DNS/IPv6/WebRTC, battery and accessibility.
- Update README, security policy, privacy policy, support/troubleshooting and `HANDOVER_FOR_NEXT_AI.md` with paths, verification evidence and unresolved device-only items.
- Push `hardening/v4`, require green CI, then fast-forward `main` without force.
