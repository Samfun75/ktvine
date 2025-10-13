# ktvine

Kotlin Multiplatform library that mirrors the core functionality of pywidevine: open/close Widevine sessions, build signed license requests from PSSH, verify and parse license responses, and expose decrypted content keys.

Built on the same protobuf models as pywidevine and designed to run on JVM and Android targets.

- Open/close sessions
- Build SignedMessage(LICENSE_REQUEST) from a Widevine PSSH
- Verify SignedMessage(LICENSE) responses, decrypt keys
- Parse/build PSSH boxes (Widevine ⇄ PlayReady), extract KIDs

See also: API docs in docs/API.md

## Installation

Gradle (Kotlin DSL):

```kotlin
dependencies {
    implementation("io.github.samfun75.ktvine:library:${version}")
}
```

This is a Kotlin Multiplatform library. The artifact publishes for JVM and Android. iOS/Linux targets may be added later.

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
val sessionId = cdm.open()
// Optional: service cert as raw SignedDrmCertificate bytes or SignedMessage-wrapped bytes
// cdm.setServiceCertificate(sessionId, serviceCertBytes)
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

val keys = cdm.getKeys(sessionId) // List<Key>
keys.forEach { println(it) }

cdm.close(sessionId)
```

## PSSH utilities

PSSH parsing and conversion helpers are included:

- Construct from Base64 or bytes: `PSSH(psshBase64)`, `PSSH(psshBytes)`
- Extract KIDs: `pssh.keyIds()` → List<UUID>
- Export: `pssh.dump()` (bytes), `pssh.dumps()` (Base64)
- Convert between systems:
  - `pssh.toWidevine()`
  - `pssh.toPlayready(laUrl, luiUrl, dsId, decryptorSetup, customData)` (builds v4.3.0.0 header)
- Create new boxes: `PSSH.new(systemId, keyIds = ..., initData = ..., version = 0/1)`
- Overwrite KIDs (Widevine): `pssh.setKeyIds(listOf(uuid1, uuid2))`

## Error handling

Public methods throw typed exceptions you can catch:

- TooManySessionsException
- InvalidSessionException
- InvalidInitDataException
- InvalidLicenseTypeException
- DecodeException
- SignatureMismatchException
- ValueException

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

## API reference

KDoc is provided throughout the codebase; you can also read a compact overview in docs/API.md.

## License

See LICENSE.
