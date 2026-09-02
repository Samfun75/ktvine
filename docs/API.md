# ktvine — conceptual guide

The per-symbol reference is generated from the source by Dokka and published to
**<https://samfun75.github.io/ktvine/>**, covering `ktvine`, `ktvine-remote` and
`ktvine-serve`. Build it locally with `./gradlew dokkaHtmlMultiModule` and open
`build/dokka/htmlMultiModule/index.html`.

This page explains only the things a signature cannot: what the pieces are for, what order
to call them in, and where the sharp edges are. It deliberately lists no parameter tables,
because those are what drifted last time.

## What this library is

ktvine implements the **client half** of the Widevine license exchange, ported from
[pywidevine](https://github.com/devine-dl/pywidevine). It loads a device, builds a signed
license request from a PSSH, verifies and parses the server's response, and hands back the
decrypted content keys.

It ships **no HTTP client**. You move the bytes to and from your own license server. It also
does no device provisioning, and there is no PlayReady CDM — see "PlayReady scope" below.

## The flow

The call sequence and a runnable example live in the [README](../README.md#quickstart).
What it does not say:

Everything on `Cdm` is `suspend`, and a `Cdm` is safe to share between coroutines: it holds
one mutex for the session map and one per session, and never holds both at once.

A `Cdm` allows `Cdm.MAX_NUM_OF_SESSIONS` (16) concurrent sessions. `close` frees a slot.

## Sessions and ordering

`parseLicense` only works for a session that has already produced a challenge: the request
context needed to derive the keys is stored by `getLicenseChallenge`, keyed by request id,
and consumed by `parseLicense`. Calling `parseLicense` without a prior challenge — or twice
for the same one — raises `InvalidContextException`.

After a successful `parseLicense`, `getLicense(sessionId)` returns the decoded `License`, so
you can read `policy` (`can_persist`, `can_renew`, `rental_duration_seconds`,
`renewal_server_url`, …) for offline or renewal flows.

`getLicenseChallenge(requestType = RENEWAL | RELEASE)` builds a request that references the
license already parsed for the session instead of the content, so the new context is filed
under that license's request id — the only id the server can quote back. The round trip is
covered offline by `CdmOfflineLicenseTest`, but **has never been exercised against a live
server**, and it still signs with the device key rather than `macKeyClient`; see the caveat
in `docs/plans/library-improvements.md`.

## PSSH input

The [README](../README.md#pssh-utilities) lists what `PSSH(...)` accepts. The part that
matters here is that it is a *cascade*, tried in order — ISOBMFF box, bare `WidevinePsshData`
CENC header, bare PlayReady header or PRO, then the lenient catch-all. A bare CENC header is
accepted only when re-encoding reproduces the input byte for byte, because protobuf will
happily "parse" many non-protobuf blobs. `strict = true` removes the catch-all, which is what
you want when the bytes came from a manifest rather than from a caller.

## Key IDs

Key IDs are messier than they look, and ktvine follows pywidevine here:

- A 16-byte `KeyContainer.id` is a big-endian UUID.
- An all-digits ASCII id is a **decimal number**, not bytes. Widevine's own test content
  sends `"0000000000000001"`, which is the UUID `…-000000000001`, not `3030…3031`.
- A short id is zero-padded on the right.
- Raw id bytes are **never** Base64. Use `String.kidToUuid()` for genuinely Base64 input.

**PlayReady KIDs are little-endian GUIDs** and ktvine byte-swaps them on read and write.
This is a deliberate divergence from pywidevine, which does not swap and therefore disagrees
with the manifest's own `cenc:default_KID`. The manifest is treated as the authority.

## Errors

Everything the library throws derives from `KtvineException`, so one catch suffices; the
subtypes are listed in the [README](../README.md#error-handling).

The guarantee worth relying on: malformed input from a license server surfaces as
`DecodeException`, never as a platform null-pointer error. Every optional protobuf field the
protocol makes mandatory is checked, so a hostile or broken response cannot reach you as an
`NPE` from inside the parser.

## Logging

The library is quiet by default — only warnings and above reach the platform log. Raise it
while debugging an exchange:

```kotlin
KtvineLog.setMinSeverity(Severity.Verbose)   // or setLogger(yourKermitLogger)
```

Verbose includes a hex dump of the init data being parsed, which you may consider sensitive.

## Manifests

`Manifests` pulls init data out of a manifest so you do not have to:

```kotlin
val pssh = Manifests.psshFromMpd(mpdXml).first()          // Widevine by default
val pr   = Manifests.psshFromMpd(mpdXml, PSSH.PLAYREADY_SYSTEM_ID)
val hls  = Manifests.psshFromM3u8(playlistText)           // inline #EXT-X-KEY data: URIs
```

`Manifests.defaultKeyIdsFromMpd(xml)` returns the manifest's own `cenc:default_KID` values,
which is a useful independent cross-check of what a PSSH claims.

Everything is parsed as real XML, not with regexes, and duplicate `ContentProtection`
entries collapse. Nothing here touches the network.

## Key rotation

`PSSH.cryptoPeriodIndex` and `PSSH.cryptoPeriodSeconds` expose what a rotating header
declares. To fetch the licence for the next period, retarget the PSSH and request again:

```kotlin
pssh.setCryptoPeriodIndex(pssh.cryptoPeriodIndex!! + 1)
val challenge = cdm.getLicenseChallenge(sessionId, pssh)
```

## Remote CDM and serving one

`ktvine-remote` puts the device on a server and `ktvine-serve` is that server; the
[README](../README.md#ktvine-remote-keep-the-device-on-a-server) covers both dependencies
and usage. The parts a signature will not tell you:

**They speak pywidevine's `serve.py` protocol, not a ktvine-specific one.** That is
deliberate: ktvine's `RemoteCdm` can drive a `pywidevine serve` instance, and pywidevine's
own `RemoteCdm` can drive `ktvine-serve`. Both directions are exercised by hand against the
real implementations; keep it that way when extending either side.

**pywidevine's client opens with a `HEAD /` probe** and refuses any server whose `Server`
header does not name a `pywidevine serve` version it supports. `ServeConfig.serverHeader`
defaults to a string that identifies ktvine while declaring the protocol version it
implements, which is what makes that client work. Change it and you lock those clients out.

**A licence server's JSON `null` means absent**, not the string `"null"` — relevant if you
extend the client, because the two are easy to confuse in kotlinx-serialization and a real
`pywidevine serve` sends `null` for an unset service certificate.

`forcePrivacyMode` on the server rejects a challenge whose session has no service
certificate, and that rejection reaches the caller as a typed `RemoteCdmException` carrying
the server's own message rather than as a transport error.

Only `RequestType.NEW` crosses the wire — the protocol has no renewal endpoint, and
`RemoteCdm` rejects `RENEWAL`/`RELEASE` locally rather than sending something the server
cannot honour.

## Multiplatform notes

`commonMain` is pure Kotlin. Targets are JVM, Android, iOS (x64, arm64, simulator arm64)
and linuxX64.

- `kotlin.uuid.Uuid` is still experimental in Kotlin 2.2 and appears in this library's public
  API, so **consumers must opt in** (`@OptIn(ExperimentalUuidApi::class)` or the compiler
  flag).
- `Device.load` / `Device.dump` take an okio `FileSystem` explicitly, because
  `FileSystem.SYSTEM` is not part of okio's common API. Pass it from a platform source set.
- AES-CMAC is implemented in-tree per RFC 4493, because no cryptography-kotlin provider
  offers it on every target. It is pinned by the RFC vectors on every platform.

## PlayReady scope

PlayReady is supported **only** at the PSSH-header level: parse a PlayReady Object to
extract KIDs, and convert Widevine ⇄ PlayReady. There is no PlayReady CDM — no device
provisioning, no XMR license parsing, no ECC P-256, no license acquisition, and no Embedded
License Store. This matches pywidevine's scope; a real PlayReady CDM is a separate protocol.

Within that scope, only v4.3.0.0 headers can be generated. Headers are parsed as real XML
(via xmlutil), with the key id path enforced per version — `DATA/KID` for 4.0.0.0,
`DATA/PROTECTINFO/KID` for 4.1.0.0, `DATA/PROTECTINFO/KIDS/KID` for 4.2.0.0 and 4.3.0.0 —
so a `<KID>` somewhere else in the document is not mistaken for a real one.
