# ktvine

Kotlin Multiplatform library that mirrors the core functionality of pywidevine: open/close Widevine sessions, build signed license requests from PSSH, verify and parse license responses, and expose decrypted content keys.

Built on the same protobuf models as pywidevine and designed to run on JVM, Android, iOS and Linux targets.

- Open/close sessions
- Build SignedMessage(LICENSE_REQUEST) from a Widevine PSSH
- Verify SignedMessage(LICENSE) responses, decrypt keys
- Parse/build PSSH boxes (Widevine ⇄ PlayReady), extract KIDs

**API reference:** <https://samfun75.github.io/ktvine/> — conceptual guide in
[docs/API.md](docs/API.md).

## Installation

Gradle (Kotlin DSL):

```kotlin
dependencies {
    implementation("io.github.samfun75:ktvine:1.0.0-RC1")
    // Optional: talk to a pywidevine-compatible CDM server instead of holding a device.
    // implementation("io.github.samfun75:ktvine-remote:1.0.0-RC1")
    // Optional (JVM only): serve your own CDM over that same protocol.
    // implementation("io.github.samfun75:ktvine-serve:1.0.0-RC1")
}
```

This is a Kotlin Multiplatform library, published for JVM, Android, iOS (x64, arm64,
simulator arm64) and linuxX64.

Two things to know before you start:

- **The `Cdm` API is `suspend`.** Call it from a coroutine. A `Cdm` is safe to share
  between coroutines.
- **`kotlin.uuid.Uuid` appears in the public API** and is still experimental in Kotlin 2.2,
  so you must opt in — `@OptIn(ExperimentalUuidApi::class)`, or the
  `-opt-in=kotlin.uuid.ExperimentalUuidApi` compiler flag.

The per-symbol API reference is generated with Dokka and published at
<https://samfun75.github.io/ktvine/>; [docs/API.md](docs/API.md) is the conceptual guide.

## Quickstart

The typical flow is the same as pywidevine, adapted to Kotlin:

1) Load a Widevine device (WVD v2) and create a CDM

```kotlin
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.cdm.Cdm

val device = Device.loads(base64Wvd) // or Device.loads(bytes)
val cdm = Cdm.fromDevice(device)
```

2) Open a session and optionally set a service certificate (privacy mode)

```kotlin
val sessionId = cdm.open() // suspend, like the rest of Cdm
// Optional: raw SignedDrmCertificate bytes, SignedMessage-wrapped bytes, or Base64.
// Cdm.COMMON_PRIVACY_CERT is bundled; otherwise POST Cdm.SERVICE_CERTIFICATE_CHALLENGE
// to your license server to obtain one.
// cdm.setServiceCertificate(sessionId, Cdm.COMMON_PRIVACY_CERT)
```

3) Build a license challenge from a PSSH

```kotlin
import org.samfun.ktvine.core.PSSH

val pssh = PSSH(psshBase64) // or PSSH(psshBytes)
val challenge = cdm.getLicenseChallenge(
    sessionId = sessionId,
    pssh = pssh
)
// Send `challenge` bytes to your Widevine license server (not provided by this library)
```

4) Parse the license response and read keys

```kotlin
// licenseMessage: SignedMessage(LICENSE) payload from your server (raw bytes)
cdm.parseLicense(sessionId, licenseMessage)

val keys = cdm.getKeys(sessionId) // List<Key>; filter by KeyType with getKeys(sessionId, type)
keys.forEach { println(it) }

cdm.close(sessionId)
```

## PSSH utilities

PSSH parsing and conversion helpers are included:

- Construct from Base64 or bytes: `PSSH(psshBase64)`, `PSSH(psshBytes)`. Besides a full
  `pssh` box these also accept a bare Widevine CENC header, a bare PlayReady header or
  PlayReady Object, and — unless you pass `strict = true` — any custom init data, wrapped
  verbatim in a v0 Widevine box.
- Extract KIDs: `pssh.keyIds()` → `List<Uuid>` (`kotlin.uuid.Uuid`)
- Export: `pssh.export()` (bytes), `pssh.exportBase64()` (Base64)
- Multi-DRM init segments: `PSSH.parseAll(bytes)`, `PSSH.fromInitSegment(bytes, systemId)`
- Encryption scheme: `pssh.encryptionScheme` (`AESCTR`, `AESCBC`, …), carried through conversion
- Convert between systems:
  - `pssh.toWidevine()`
  - `pssh.toPlayready(laUrl, luiUrl, dsId, decryptorSetup, customData)` (builds v4.3.0.0 header)
- Create new boxes: `PSSH.new(systemId, keyIds = ..., initData = ..., version = 0/1)`
- Overwrite KIDs: `pssh.setKeyIds(listOf(uuid1, uuid2))` (Widevine and PlayReady)

## Error handling

Public methods throw typed exceptions you can catch:

All of them derive from `KtvineException`, so a single catch is enough:

- TooManySessionsException
- InvalidSessionException
- InvalidContextException
- InvalidInitDataException
- InvalidLicenseMessageException
- DecodeException
- SignatureMismatchException
- NoKeysLoadedException
- DeviceMismatchException
- ValueException
- InvalidBoxException

## Differences from pywidevine

- No built-in HTTP client or license server integration. You send/receive bytes yourself.
- No device provisioning included. Use a valid WVD v2 file as with pywidevine.
- Uses Kotlin coroutines-friendly, multiplatform-safe crypto (cryptography-kotlin).
- Protobuf models are generated with Square Wire and are compatible with pywidevine’s schemas.

## Minimal example (JVM)

```kotlin
suspend fun main() {
    val device = Device.loads(System.getenv("WVD_BASE64"))
    val cdm = Cdm.fromDevice(device)
    val session = cdm.open()

    val pssh = PSSH(System.getenv("PSSH_BASE64"))
    val challenge = cdm.getLicenseChallenge(session, pssh)

    val licenseMessage: ByteArray = postToYourServer(challenge) // implement yourself
    cdm.parseLicense(session, licenseMessage)

    cdm.getKeys(session).forEach { println(it) }
    cdm.close(session)
}
```

## ktvine-remote — keep the device on a server

The device's private key never enters your process: every operation is an HTTP call to a
[pywidevine-compatible](https://github.com/devine-dl/pywidevine) CDM server, so one device can
back many clients. It implements the same `CdmApi` as `Cdm`, and you supply the Ktor engine,
so this module picks none for you.

```kotlin
dependencies {
    implementation("io.github.samfun75:ktvine-remote:1.0.0-RC1")
    implementation("io.ktor:ktor-client-cio:3.0.3") // any Ktor engine you like
}
```

```kotlin
val cdm: CdmApi = RemoteCdm(
    client = HttpClient(CIO),
    baseUrl = "https://cdm.example.com",
    deviceName = "my_device",
    secret = System.getenv("KTVINE_SECRET"),
    // Optional: open() then refuses a server holding a different device.
    expectedSystemId = 4464,
    expectedSecurityLevel = 3,
)

val session = cdm.open()
try {
    val challenge = cdm.getLicenseChallenge(session, PSSH(psshBase64))
    cdm.parseLicense(session, postToYourLicenseServer(challenge))
    cdm.getKeys(session).forEach { println("${it.kid}: ${it.key.toHexString()}") }
} finally {
    cdm.close(session)
}
```

`RequestType.RENEWAL` and `RELEASE` are rejected locally — the serve protocol has no endpoint
for them.

## ktvine-serve — run your own CDM server

The mirror image: hold the device once and serve it over that same protocol, so both ktvine's
`RemoteCdm` and pywidevine's own client can drive it. This module ships **routing only** — you
mount it in your own Ktor application and choose the engine. JVM only, because Ktor's server
engines do not span the targets the client does.

```kotlin
dependencies {
    implementation("io.github.samfun75:ktvine-serve:1.0.0-RC1")
    implementation("io.ktor:ktor-server-cio:3.0.3") // you pick the engine
}
```

```kotlin
val config = ServeConfig(
    devices = mapOf("my_device" to Device.loads(wvdBytes)),
    users = mapOf(
        System.getenv("KTVINE_SECRET") to ServeUser("alice", devices = setOf("my_device")),
    ),
    // Refuse a challenge whose session has no service certificate.
    forcePrivacyMode = true,
)

embeddedServer(CIO, port = 8786) {
    routing { ktvineCdm(config) }
}.start(wait = true)
```

Callers authenticate with an `X-Secret-Key` header. The device's private key never leaves the
server, so treat those secrets as credentials and serve this over TLS.

## API reference

Every public declaration carries KDoc. The generated reference for all three modules lives at
<https://samfun75.github.io/ktvine/>, and [docs/API.md](docs/API.md) is the conceptual guide
that explains what a signature cannot. Build the reference locally with:

```
./gradlew dokkaHtmlMultiModule   # -> build/dokka/htmlMultiModule/index.html
```

## License

See LICENSE.

---

Built with [Claude Code](https://claude.com/claude-code).
