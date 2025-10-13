# ktvine API Reference

This document summarizes the public surface of the ktvine library. It’s organized by package and class, with short contracts for inputs/outputs and error modes.

- Target platforms: JVM and Android (Kotlin Multiplatform).
- Protobuf models: generated via Square Wire and compatible with pywidevine schemas.

Contents
- org.samfun.ktvine.cdm
- org.samfun.ktvine.core
- org.samfun.ktvine.crypto
- org.samfun.ktvine.utils

---

org.samfun.ktvine.cdm

Cdm
- Purpose: Open/close sessions, craft LICENSE_REQUEST messages, verify/parse LICENSE responses, and expose decrypted keys.
- Construction
  - static fromDevice(device: Device): Cdm
    - Input: a parsed Widevine Device (WVD v2)
    - Output: new Cdm instance bound to that device
- Session management
  - open(): ByteString
    - Output: session id
    - Errors: TooManySessionsException if >16 sessions
  - close(sessionId: ByteString)
    - Errors: InvalidSessionException if unknown id
- Service certificate (privacy mode)
  - setServiceCertificate(sessionId: ByteString, certificate: ByteArray?): String?
    - Input: raw SignedDrmCertificate bytes or SignedMessage-wrapped; null clears current
    - Output: provider id; when clearing, previous provider id
    - Errors: InvalidSessionException, DecodeException, SignatureMismatchException
  - setServiceCertificate(sessionId: ByteString, certificateBase64: String?): String?
    - Input: Base64 version of above; null clears
    - Output/Errors: same as overload
  - getServiceCertificate(sessionId: ByteString): SignedDrmCertificate?
    - Output: current certificate (if any)
    - Errors: InvalidSessionException
- License flow
  - getLicenseChallenge(sessionId: ByteString, pssh: PSSH, licenseType: LicenseType = STREAMING, privacyMode: Boolean = true): ByteArray
    - Input: session id, parsed PSSH, optional license type and privacy mode flag
    - Output: SignedMessage(LICENSE_REQUEST) bytes
    - Notes: Stores internal request context for parseLicense
    - Errors: InvalidSessionException, InvalidInitDataException
  - parseLicense(sessionId: ByteString, licenseMessage: ByteArray)
    - Input: SignedMessage(LICENSE) bytes from license server
    - Effects: Verifies MAC/signature, decrypts keys, stores on session
    - Errors: InvalidSessionException, InvalidLicenseTypeException, DecodeException, SignatureMismatchException
  - getKeys(sessionId: ByteString, type: License.KeyContainer.KeyType? = null): List<Key>
    - Output: decrypted keys; optional type filter
    - Errors: InvalidSessionException

---

org.samfun.ktvine.core

Device
- Purpose: Represents a Widevine Device (WVD v2), including client id, private key, and metadata.
- Properties: type (DeviceTypes), securityLevel (Int), flags (Map), privateKeyDer (ByteArray), clientId (ClientIdentification), vmp (FileHashes?), systemId (Int)
- static loads(data: ByteArray): Device
  - Input: WVD v2 bytes (magic "WVD", version 2)
  - Output: Device
  - Errors: ValueException (bad magic/version/lengths)
- static loads(data: String): Device
  - Input: Base64-encoded WVD v2
  - Output/Errors: as above
- static buildWvdV2(type: DeviceTypes, securityLevel: Int, privateKeyDer: ByteArray, clientIdBytes: ByteArray): ByteArray
  - Output: raw WVD v2 bytes for storage/transport

DeviceTypes
- Enum: CHROME(1), ANDROID(2)

Key
- Purpose: Decrypted content key (KID + key bytes), with optional permissions for OPERATOR_SESSION.
- Properties: type (String), kid (UUID), key (ByteArray), permissions (List<String>)
- static fromContainer(container: License.KeyContainer, encKey: ByteArray): Key
  - Input: protobuf key container and content decryption key (CEK)
  - Output: decrypted Key

Session (internal)
- Holds session id, optional service certificate, request contexts, and decrypted keys.

PSSH
- Purpose: Parse/build PSSH boxes; convert between Widevine and PlayReady; extract KIDs.
- Constructors: PSSH(base64: String), PSSH(bytes: ByteArray), PSSH(box: PsshBox)
- Properties: initData: ByteArray (raw header content)
- keyIds(): List<UUID>
  - Output: list of KIDs if available (WV/PlayReady)
  - Errors: ValueException (unsupported format)
- dump(): ByteArray / dumps(): String
  - Output: PSSH box in bytes/Base64
- toWidevine()
  - Effect: convert current content to Widevine PSSH
  - Errors: ValueException if already Widevine
- toPlayready(laUrl: String? = null, luiUrl: String? = null, dsId: ByteArray? = null, decryptorSetup: String? = null, customData: String? = null)
  - Effect: convert to PlayReady v4.3.0.0 with optional fields
  - Errors: ValueException if already PlayReady
- setKeyIds(keyIds: List<UUID>)
  - Effect: overwrite KIDs (for Widevine only)
  - Errors: ValueException if not Widevine
- setKeyIdsAny(keyIds: List<Any>)
  - Effect: convenience wrapper accepting UUID | String(hex/base64) | ByteArray
- static parseKeyIds(keyIds: List<Any>): List<UUID>
  - Output: normalized UUID list; throws IllegalArgumentException on bad types
- static new(systemId: UUID, keyIds: List<UUID>? = null, initData: Any? = null, version: Int = 0, flags: Int = 0): PSSH
  - Output: new PSSH object; validates version/keyIds/initData combinations
  - Errors: ValueException on invalid combinations or types

---

org.samfun.ktvine.crypto

Top-level helpers (all suspend where crypto is invoked):
- rsaPssSignSha1(privateKeyDer: ByteArray, data: ByteArray): ByteArray
- rsaPssVerifySha1(publicKeyDer: ByteArray, data: ByteArray, signature: ByteArray): Boolean
- rsaOaepEncrypt(publicKeyDer: ByteArray, data: ByteArray): ByteArray
- rsaOaepDecrypt(privateKeyDer: ByteArray, data: ByteArray): ByteArray
- aesCmac(key: ByteArray, data: ByteArray): ByteArray
- aesCbcDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray
- aesCbcDecryptNoPadding(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray (alias)
- aesCbcEncryptNoPadding(key: ByteArray, iv: ByteArray, plaintextNoPad: ByteArray): ByteArray
- hmacSha256(key: ByteArray, data: ByteArray): ByteArray
- randomBytes(count: Int): ByteArray
- pkcs7Pad(data: ByteArray, blockSize: Int = 16): ByteArray
- pkcs7Unpad(data: ByteArray, blockSize: Int = 16): ByteArray

Notes
- Private key inputs use PKCS#1 DER; public keys use X.509 DER.
- AES-CBC encrypt helper expects caller-provided PKCS#7 padded plaintext.

---

org.samfun.ktvine.utils

Extensions
- UUID.toByteArray(): ByteArray
- ByteString.uuidFromByteString(): UUID
- ByteString.uuidFromHexByteString(): UUID
- ByteString.uuidFromByteArray(): UUID (numeric representation)
- Int.toLEU16(): ByteArray
- Int.toLEU32(): ByteArray
- ByteArray.toHexString(): String
- ByteString?.kidToUuid(): UUID

Types
- typealias PsshBox = ProtectionSystemSpecificHeaderBox (mp4parser)

Exceptions
- KtvineException (base)
- TooManySessionsException
- InvalidSessionException
- DecodeException
- SignatureMismatchException
- InvalidInitDataException
- InvalidLicenseTypeException
- ValueException
- InvalidBoxException

---

Usage Notes and Edge Cases
- Always call Cdm.getLicenseChallenge before parseLicense; the request context is required to verify and decrypt.
- For privacy mode, set a service certificate prior to building the license challenge and leave privacyMode=true.
- PSSH.keyIds() attempts WV first, then PlayReady; some legacy or nonconforming PSSH payloads may not be supported.
- Key.fromContainer returns raw key bytes after PKCS#7 unpadding; if the container held unpadded data, the original bytes are returned.
- Crypto operations are suspend and should be called from a coroutine context.

