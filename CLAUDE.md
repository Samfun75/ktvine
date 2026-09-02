# CLAUDE.md

Guidance for Claude Code when working in this repository.

## What this project is

**ktvine** is a Kotlin Multiplatform port of [pywidevine](https://github.com/devine-dl/pywidevine).
It implements the client half of the Widevine DRM license exchange: load a device
(WVD), open a session, build a signed `LICENSE_REQUEST` from a PSSH, verify and
parse the server's `LICENSE` response, and expose the decrypted content keys.

It deliberately does **not** ship an HTTP client, a license-server proxy, or device
provisioning. Callers move bytes to and from their own license server.

- Maven coordinates: `io.github.samfun75:ktvine`
- Current version: `1.0.0` (declared once, in `gradle/libs.versions.toml`)
- License: Apache-2.0
- Repo: https://github.com/samfun75/ktvine

## Repository layout

```
build.gradle.kts              root; all plugins declared with `apply false`
settings.gradle.kts           three modules: :library, :remote, :serve
gradle/libs.versions.toml     version catalog — the only place to bump deps
gradle.properties             configuration-cache + build-cache ON
docs/API.md                   conceptual guide; the symbol reference is Dokka-generated
docs/plans/                   implementation plans — git-ignored, local only
.github/workflows/gradle.yml  CI: `check` on ubuntu, iosSimulatorArm64Test on macos
.github/workflows/docs.yml    CI: Dokka HTML to GitHub Pages
.github/workflows/publish.yml CI: publishToMavenCentral on GitHub release

library/src/
  commonMain/proto/license_protocol.proto   Widevine protobuf schema (proto2, 754 lines)
  commonMain/kotlin/org/samfun/ktvine/
    cdm/Cdm.kt            Cdm — session lifecycle, challenge, license parsing
    cdm/CdmApi.kt         CdmApi — the subset Cdm and RemoteCdm both implement
    core/Device.kt        Device, DeviceTypes — WVD v1 migrate, v2 parse/build/dump
    core/Key.kt           Key — decrypted content key
    core/PSSH.kt          PSSH — box parse/build, Widevine <-> PlayReady
    core/PlayreadyHeader.kt  WRMHEADER parse/build via the xmlutil pull parser
    core/Manifests.kt     PSSH + default_KID extraction from DASH/HLS manifests
    core/Session.kt       Session — per-session mutable state
    crypto/Crypto.kt      RSA-PSS/OAEP, AES-CMAC/CBC, HMAC, PKCS#7
    utils/Extensions.kt   Uuid/byte/hex/XML helpers, UTF-16LE codec (pure common code)
    utils/Exceptions.kt   KtvineException hierarchy
    utils/KtvineLog.kt    the single Kermit sink; Warn by default
    utils/Protobuf.kt     decodeExact — partial-parse rejection
  commonTest/…/AesCmacTest.kt       RFC 4493 CMAC + AES-CBC/HMAC vectors (runs on all targets)
  commonTest/…/PSSHTest.kt          PSSH round-trips (pure, no fixtures)
  commonTest/…/DeviceCommonTest.kt  Device negative cases
  commonTest/resources/device/{widevine,playready}/  BINARY FIXTURES — see "Secrets" below
  commonTest/resources/playlist/    *.mpd / *.m3u8 manifests used by tests
  jvmAndAndroidTest/…/TestFixtures.kt  classpath fixture loader shared by both JVM test sets
  jvmTest/…/CDMJvmTest.kt           RSA-PSS unit test (hermetic)
  jvmTest/…/CdmProxyIntegrationTest.kt  end-to-end vs proxy.widevine.com (NETWORK, opt-in)
  jvmTest/…/DeviceJvmTest.kt        WVD parse/build against fixtures
  androidHostTest/…/DeviceAndroidTest.kt  same, on the Android host JVM

remote/src/
  commonMain/…/RemoteCdm.kt         CdmApi over pywidevine's serve.py HTTP protocol
  commonTest/…/RemoteCdmTest.kt     wire-format tests against Ktor MockEngine

serve/src/                          JVM only: Ktor server engines are not as portable
  commonMain/…/ServeConfig.kt       devices, users, forced privacy, Server header
  commonMain/…/Routing.kt           Route.ktvineCdm — the serve protocol, routing only
  commonTest/…/ServeRoutingTest.kt  the wire contract plus ktvine's own client end to end
```

## Build system

Kotlin `2.2.20`, AGP `8.13.0`, Gradle `8.14.3`, JDK target 11 for Android
compilations. Plugins: `kotlinMultiplatform`, `com.android.kotlin.multiplatform.library`
(the newer AGP KMP plugin, not `com.android.library`), `com.squareup.wire`,
`com.vanniktech.maven.publish`.

**Targets: `jvm()`, `androidLibrary`, `iosX64`, `iosArm64`, `iosSimulatorArm64`,
`linuxX64`.** All are enabled, and the CI matrix runs `linuxX64Test` on ubuntu and
`iosSimulatorArm64Test` on macos. `commonMain` is pure Kotlin — no JDK types.

`kotlin.uuid.Uuid` and `kotlin.time.Clock` are still experimental in Kotlin 2.2, and `Uuid`
appears in the public API, so the build opts in project-wide via `compilerOptions.optIn`
and **consumers must opt in too**.

Wire generates protobuf models into `org.samfun.ktvine.proto` with
`buildersOnly = true`, so generated messages are constructed via named constructor
arguments and copied with `.copy(...)`. `android = true` is set for the Android
compilation and `false` for JVM.

Dependencies (commonMain):
- `api(wire-runtime)` — this is what transitively exposes **okio** (`ByteString`,
  `Buffer`) to the whole codebase, including consumers. Nothing declares okio directly.
- `implementation(bundles.cryptography)` — whyoleg cryptography-kotlin `0.5.0`:
  `core` + `provider-optimal`. BouncyCastle was dropped once AES-CMAC moved in-tree; the
  plain JDK provider covers everything else.
- `implementation(coroutines-core)` — only for `kotlinx.coroutines.sync.Mutex`, which
  guards `Cdm`'s session state.
- `implementation(xmlutil-core)` — PlayReady headers and DASH manifests are parsed with a
  real pull parser. Only `core`: no kotlinx-serialization, no compiler plugin. Commit
  `3b674df` removed a much heavier setup (three deps + the serialization plugin); this is
  deliberately the minimal replacement.
- `implementation(kermit)` — logging, routed through `KtvineLog`.

The `:remote` module adds `ktor-client-core` (engine-agnostic) and
`kotlinx-serialization-json` used only through its runtime `JsonElement` API. `:serve` adds
`ktor-server-core` on the same terms — routing only, no engine — and is JVM-only because
server engines do not span the six targets the client does. Both are opt-in artifacts
(`ktvine-remote`, `ktvine-serve`); the core library keeps zero networking dependencies.

Common commands:
```powershell
.\gradlew.bat :library:compileKotlinJvm            # fastest sanity check
.\gradlew.bat :library:jvmTest                     # hermetic; excludes *IntegrationTest
.\gradlew.bat :library:jvmTest --tests "org.samfun.ktvine.PSSHTest"
.\gradlew.bat :library:testAndroidHostTest
.\gradlew.bat :library:integrationTest             # NETWORK: live proxy.widevine.com
.\gradlew.bat :library:publishToMavenLocal
```

Note: `publishToMavenCentral` must be run with `--no-configuration-cache`
(see `publish.yml:23`). Signing is gated on the `PUBLISH` env var being set.

## The protocol flow (what the code actually does)

1. **`Device.loads(bytes|base64)`** parses a WVD v2 blob:
   `"WVD"` magic, `u8` version (must be 2), `u8` type, `u8` security level,
   `u8` flags (read then **discarded**), `u16be` private-key length + PKCS#1 DER
   key, `u16be` client-id length + serialized `ClientIdentification`.
   `systemId` is dug out of `clientId.token` → `SignedDrmCertificate` →
   `DrmCertificate.system_id`. `vmp` is best-effort decoded from `clientId.vmp_data`.

2. **`Cdm.fromDevice(device)`** keeps only `type`, `clientId`, `privateKeyDer`.

3. **`Cdm.open()`** (suspend) creates a `Session` with a random 16-byte id and a number
   from a monotonic counter, stored in a `LinkedHashMap<ByteString, Session>`. Capped at
   `Cdm.MAX_NUM_OF_SESSIONS` (16).

4. **`Cdm.setServiceCertificate(...)`** (optional, for privacy mode) accepts either a
   `SignedMessage` wrapping a `SignedDrmCertificate` or a bare `SignedDrmCertificate`,
   verifies its signature with RSA-PSS/SHA-1 against the hardcoded Google root
   certificate (`ROOT_SIGNED_CERT_B64` in `Cdm.kt`), and stores it on the session.

5. **`Cdm.getLicenseChallenge(...)`** builds a `LicenseRequest`. If a service cert is
   set and `privacyMode` is true, `client_id` is replaced by an
   `EncryptedClientIdentification`: the serialized client id is PKCS#7-padded and
   AES-CBC encrypted under a random 16-byte key/IV, and that key is RSA-OAEP
   encrypted to the service certificate's public key. The serialized `LicenseRequest`
   is signed with RSA-PSS/SHA-1 using the device private key and wrapped in a
   `SignedMessage(LICENSE_REQUEST)`.
   Crucially, it also derives and stores the **context** for this request:
   ```
   encCtx = "ENCRYPTION"     || 0x00 || licenseRequestBytes || be32(128)
   macCtx = "AUTHENTICATION" || 0x00 || licenseRequestBytes || be32(512)
   ```
   keyed by `request_id` in `session.context`.

6. **`Cdm.parseLicense(...)`** decodes the `SignedMessage(LICENSE)`, looks up the
   context by `license.id.request_id`, RSA-OAEP decrypts `session_key` with the
   device private key, then derives keys via AES-CMAC in NIST SP 800-108 counter mode:
   ```
   encKey       = CMAC(sessionKey, 0x01 || encCtx)
   macKeyServer = CMAC(sessionKey, 0x01 || macCtx) || CMAC(sessionKey, 0x02 || macCtx)
   macKeyClient = CMAC(sessionKey, 0x03 || macCtx) || CMAC(sessionKey, 0x04 || macCtx)
   ```
   It verifies `HMAC-SHA256(macKeyServer, oemcrypto_core_message || msg)` against
   `sm.signature` (the `oemcrypto_core_message` prefix is the OEMCrypto v16+ change),
   then AES-CBC decrypts each `KeyContainer.key` under `encKey` with the container IV
   and PKCS#7-unpads. Keys land in `session.keys`; the context entry is removed.

7. **`Cdm.getKeys(sessionId, type?)`** returns a snapshot; **`Cdm.close(sessionId)`**
   drops the session. Both are `suspend`.

**Locking.** `Cdm` holds a `Mutex` for the session map and the counter; each `Session`
holds its own `Mutex` for its state. The two are never held at once, so they cannot
deadlock. `CdmConcurrencyJvmTest` fails if either is removed.

## PSSH handling

`PSSH` is a mutable holder of `(_systemId, _version, _flags, _keyIds, _content)`.

- `PSSH(bytes, strict = false)` / `PSSH(base64, strict = false)` apply a cascade: ISOBMFF
  box sequence → bare `WidevinePsshData` CENC header (accepted only if re-encoding
  round-trips) → bare PlayReady header/PRO (detected by a UTF-16LE `</WRMHEADER>`) →
  in lenient mode, wrap the bytes verbatim as a v0 Widevine box. `strict = true` throws
  `DecodeException` instead of that last step.
- `PSSH.parseAll(bytes|base64)` returns every `pssh` box; `PSSH.fromInitSegment(bytes,
  systemId)` picks one by DRM system. The constructors still take only the first box.
- `keyIds()` dispatches on `_systemId`: PlayReady parses the PRO, Widevine decodes the CENC
  header, and an unknown system id tries both. PlayReady KIDs are **byte-swapped** —
  they are little-endian GUIDs, and reading them big-endian (as pywidevine does) disagrees
  with the manifest's own `cenc:default_KID`.
- `encryptionScheme` surfaces PlayReady's `ALGID` or Widevine's `protection_scheme` 4CC,
  and is carried through both conversions.
- `toWidevine()` / `toPlayready(...)` rewrite `_content` and `_systemId` in place.
  `toPlayready` XML-escapes `laUrl`/`luiUrl`/`decryptorSetup` (not `customData`, which is
  raw XML by spec) and rejects headers over the u16 record limit.
- `setKeyIds()` handles Widevine and PlayReady; the PlayReady side rebuilds the PRO as
  v4.3.0.0 and carries over LA_URL / LUI_URL / DS_ID / DECRYPTORSETUP / CUSTOMATTRIBUTES.
- `export()` / `exportBase64()` re-serialize a full `pssh` box.
- `PSSH.new(systemId, keyIds, initData, version, flags)` builds synthetic boxes; passing
  only `keyIds` now populates a real CENC header or PRO rather than leaving `_content` empty.

### Scope of PlayReady support

PlayReady is supported **only** at the PSSH-header level: parse a PlayReady Object to
extract KIDs, and convert Widevine ⇄ PlayReady. There is no PlayReady CDM — no device
provisioning (`bgroupcert.dat` / `zgpriv.dat`), no XMR license parsing, no ECC P-256
crypto, no license acquisition, and no Embedded License Store (PRO record type `0x03`;
only type `0x01`, the header record, is handled). This matches pywidevine's scope. A
real PlayReady CDM is a separate protocol — see `pyplayready`.

Headers are parsed with a real pull parser (`PlayreadyHeader`, on xmlutil), with the KID
path enforced per version, and `setKeyIds()` rebuilds the PRO. Two limits remain: only
v4.3.0.0 can be *generated*, and a single document-level `ALGID` is carried through
conversion rather than the per-KID scheme v4.2.0.0+ allows.

## Error model

All library exceptions extend `KtvineException : Exception` in `utils/Exceptions.kt`:
`TooManySessionsException`, `InvalidSessionException`, `DecodeException`,
`SignatureMismatchException`, `InvalidInitDataException`, `InvalidLicenseMessageException`,
`InvalidContextException`, `NoKeysLoadedException`, `DeviceMismatchException`,
`ValueException`, `InvalidBoxException`.

Everything the library throws is now a `KtvineException` — no `require(...)` and no `!!`
on server-supplied fields. Missing-but-required protobuf fields go through the internal
`orDecodeError(field)` helper and surface as `DecodeException`. The only remaining `!!`
are on the hardcoded Google root certificate, which is a compile-time constant.

Every declared type has a throw site: `NoKeysLoadedException` from `getKeysFromEntitlement`,
`DeviceMismatchException` from `RemoteCdm.open`. Keep it that way — a declared-but-unthrown
exception is dead weight in a frozen ABI.

## The reference implementation

pywidevine is checked out locally at `C:\Users\Samfun\Code\PycharmProjects\pywidevine`.
Read `pywidevine/cdm.py`, `pssh.py`, `device.py`, `key.py`, `session.py` before
changing protocol behaviour — ktvine is meant to mirror it.

Mapping: `cdm.py` → `cdm/Cdm.kt`, `pssh.py` → `core/PSSH.kt`,
`device.py` → `core/Device.kt`, `key.py` → `core/Key.kt`, `session.py` → `core/Session.kt`,
`exceptions.py` → `utils/Exceptions.kt`, `remotecdm.py` → `remote/…/RemoteCdm.kt`,
`serve.py` → `serve/…/Routing.kt`. There is no ktvine counterpart to `main.py` (CLI) or
`Cdm.decrypt` (shaka-packager).

`:serve` reimplements the *protocol*, not the code: pywidevine is GPL-3.0-only and ktvine
is Apache-2.0, so paths, JSON field names and status codes are matched while the Kotlin and
its messages are ktvine's own. Keep it that way when extending it.

### Known divergences from pywidevine

Every item that used to sit here (bare-PSSH input, the Android request id, the
`key_control_nonce` range, partial-parse validation, `pkcs7Unpad`, `PSSH.new` key ids,
the `Cdm` constants, the `Device` file API, `systemId`/`securityLevel`, the missing
exceptions) was closed by the plan. What actually differs now:

**Deliberate, ktvine is right:**

- **PlayReady KIDs are byte-swapped.** They are little-endian GUIDs; pywidevine reads them
  big-endian (`pssh.py:276`) and so disagrees with the manifest's own `cenc:default_KID`.
  The manifest is the authority. See `swapGuidEndianness` in `utils/Extensions.kt`.
- **`Cdm.open()` compares `>=` against `MAX_NUM_OF_SESSIONS`.** pywidevine's `>` lets a
  17th session through.
- **`pkcs7Unpad` throws on bad padding.** Matches `Padding.unpad`; ktvine's old behaviour
  of returning the input handed back a failed decrypt as if it were a key.

**ktvine has more:**

- `getLicenseChallenge(requestType = RENEWAL | RELEASE)` — pywidevine has no `RequestType`
  parameter at all. See the caveat under "Known issues".
- `PSSH.encryptionScheme`, carried through both conversions (pywidevine: TODO at
  `pssh.py:265`).
- `PSSH.setKeyIds` on PlayReady boxes, and `PSSH.new(keyIds=…)` building a real PRO.
- `Cdm.getLicense`, `Cdm.getKeysFromEntitlement`, `PSSH.cryptoPeriodIndex`/`setCryptoPeriodIndex`.
- `Manifests` — no pywidevine counterpart. It parses PSSH strictly, unlike the lenient
  default the `PSSH` constructors use.

**ktvine has less:**

- **`RemoteCdm`'s device check is opt-in.** pywidevine requires the expected
  `system_id`/`security_level`; ktvine's are nullable constructor arguments, so omitting them
  accepts whatever device the server holds.
- **No `Cdm.decrypt`** (shaka-packager) and no CLI.
- **`:serve` is JVM-only and routing-only.** It ships a `Route.ktvineCdm(config)` extension
  rather than owning an engine, so the consumer picks one; pywidevine's `serve` owns aiohttp.
- **A bare `WRMHEADER` is accepted but its KIDs cannot be read.** The `PSSH` cascade stores
  it verbatim, then `keyIds()` reads the first four bytes as a PRO length and fails with
  "corrupt". pywidevine has the same hole, so this is inherited rather than introduced —
  but wrapping a bare header into a synthetic PRO on ingest would close it.

## Crypto notes

`aesCmac` is **implemented in `commonMain` per RFC 4493**, not taken from a provider. No
cryptography-kotlin 0.5.0 provider offers AES-CMAC on every target: BouncyCastle covers
JVM/Android, OpenSSL3 covers linuxX64, but neither Apple provider has it at all. CMAC is
CBC-MAC with a tweaked final block, so it is built on AES-CBC, which every provider does
have. It is pinned by the four RFC 4493 vectors in `AesCmacTest` (in `commonTest`, so they run on
native too) and, indirectly, by the live proxy test — get it wrong and every derived key is
wrong.

Everything else comes from `cryptography-provider-optimal`: RSA-PSS/SHA-1, RSA-OAEP/SHA-1,
AES-CBC, HMAC-SHA256, and `CryptographyRandom` for all randomness.

## Known issues to be aware of when editing

Ordered roughly by severity. Everything the improvement plan tracked is done and the API
is frozen at `1.0.0`; what remains is unverifiable rather than unwritten.

1. **Every target is now verified at runtime.** linuxX64 passes the full `commonTest` suite
   under WSL, and **iOS passes it on a GitHub Actions `macos-latest` runner** — the RFC 4493
   CMAC vectors, a complete offline license exchange and the XML parser all execute on the
   simulator. The `iosSimulatorArm64Test` job carries a gate that fails when the task reports
   zero executed tests or when `AesCmacTest` / `CdmOfflineLicenseTest` / `PlayreadyOracleTest`
   are missing: a Gradle test task that runs nothing still exits green, which is how iOS
   looked "passing" while being unverified. Do not remove that gate.
2. **`RemoteCdm` is verified against a live `pywidevine serve` 1.8.0.** Every endpoint was
   exercised end to end — open/close, both service-certificate calls, challenge, parse and
   get_keys — recovering all eight of Google's published keys through the server, with and
   without privacy mode. A server running `force_privacy_mode` refuses a non-privacy
   exchange and that 403 surfaces as a typed `RemoteCdmException`. Cross-testing found two
   real defects the mocks could not: `RemoteCdm` decoded a JSON `null` as the *text*
   `"null"` (pywidevine's server sends one for an unset service certificate), and its client
   opens with a `HEAD /` probe demanding a `pywidevine serve` version in the `Server`
   header. Neither live run is automated, so re-run them by hand after touching the wire
   format.
3. **Renewal is untested against a live server.** The round trip works offline
   (`CdmOfflineLicenseTest`): the context is keyed on the request id from the license the
   renewal names, which is the only id the response can echo. Two assumptions are unproven
   — that a server does echo it, and that signing with the device key is right. The proto
   says a request's algorithm comes from its certificate, which is why this does not use
   `macKeyClient`; revisit only with a real renewal to observe.
4. **Only `linuxX64Test` and the JVM/Android suites run locally.** `check` now also builds
   the metadata artifact, so a JDK-only reference in `commonMain` fails the build instead of
   silently breaking publishing — that hole is closed, do not reopen it by dropping the
   `compileCommonMainKotlinMetadata` dependency from `check`.

## Secrets and fixtures

`library/src/commonTest/resources/device/` holds real DRM provisioning material in two
subfolders: `widevine/` (`google_avd.wvd`, `google_avd.b64.txt`, `client_id.bin`,
`private_key.pem` — a real Widevine device) and `playready/` (six SL3000 PlayReady devices,
each `*.prd` + `bgroupcert.dat` + `zgpriv.dat`). `.gitignore` excludes the whole tree except
the tracked `README.md`s, plus `*.wvd`, `*.pem`, `*.prd`, `*.dat`, and `client_id.bin`
repo-wide. Do not commit them, and do not paste their contents into any output.

**The PlayReady devices are unused.** ktvine has no PlayReady CDM, so a `.prd` device does
nothing today — using one would need device provisioning, XMR license parsing and ECC P-256,
a separate effort that does not exist yet. Only `widevine/` is read by the current suite.

Tests load fixtures from the test classpath through `TestFixtures` in
`src/jvmAndAndroidTest` (paths are relative to `commonTest/resources`, e.g.
`device/widevine/google_avd.wvd`). `TestFixtures.orSkip(...)` prints an explicit `SKIP:`
line and returns `null` when a fixture is absent, so a checkout without them still goes
green without hiding the fact.

## Conventions

- Package root `org.samfun.ktvine`; Android namespace `io.github.samfun75.ktvine`;
  Maven group `io.github.samfun75`.
- Public API carries KDoc. Follow that when adding public declarations.
- Behaviour is intentionally mirrored from pywidevine. When in doubt about a
  protocol detail, match pywidevine's `cdm.py` / `pssh.py` / `device.py`.
- The version lives once, in `gradle/libs.versions.toml` (`ktvine = "..."`). The README
  install snippet must match; `publish.yml` fails the release if it or the tag disagrees.
- `explicitApi()` is on: every public declaration needs an explicit visibility and return
  type. `apiCheck` compares the ABI against `library/api/`; run `./gradlew apiDump` after
  an intentional API change.
- ktlint runs in `check`. Run `./gradlew ktlintFormat` before committing.
- Dependency versions belong in `gradle/libs.versions.toml`, never inline.
