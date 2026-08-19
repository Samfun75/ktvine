package org.samfun.ktvine.cdm

import co.touchlab.kermit.Logger
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.cdm.Cdm.Companion.fromDevice
import org.samfun.ktvine.core.*
import org.samfun.ktvine.crypto.*
import org.samfun.ktvine.proto.*
import org.samfun.ktvine.utils.*

/**
 * Widevine CDM helper that can:
 * - open/close sessions
 * - build signed license requests from a [PSSH]
 * - parse signed license responses and expose decrypted [Key]s
 *
 * Typical flow:
 * 1. Construct from a Widevine [Device] via [fromDevice]
 * 2. [open] a session and optionally [setServiceCertificate]
 * 3. Build a license challenge with [getLicenseChallenge]
 * 4. Send the challenge to a license server (not provided by this library)
 * 5. Parse the response with [parseLicense]
 * 6. Read keys with [getKeys] and [close] the session
 *
 * This class is Kotlin Multiplatform and uses the same protobuf models as pywidevine.
 */
class Cdm(
    private val deviceType: DeviceTypes,
    private val clientId: ClientIdentification,
    private val privateKeyDer: ByteArray,
    /** System id of the device this CDM was built from, or 0 when unknown. */
    val systemId: Int = 0,
    /** Security level of the device this CDM was built from, or 0 when unknown. */
    val securityLevel: Int = 0
) {
    private val sessions = linkedMapOf<ByteString, Session>()

    // Monotonic: `sessions.size + 1` repeats a number after any close/open cycle, and the
    // number becomes load-bearing once the Android request id is derived from it.
    private var sessionCounter = 0

    // Guards the map and the counter only. Session-scoped work takes Session.lock instead,
    // and the two are never held at the same time, so the pair cannot deadlock.
    private val sessionsLock = Mutex()

    private suspend fun session(sessionId: ByteString): Session =
        sessionsLock.withLock { sessions[sessionId] }
            ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")

    companion object {
        /** Maximum number of concurrently open sessions. */
        const val MAX_NUM_OF_SESSIONS: Int = 16

        /**
         * A serialized `SignedMessage(SERVICE_CERTIFICATE_REQUEST)`. POST this to a license
         * server to obtain its service certificate for privacy mode.
         */
        val SERVICE_CERTIFICATE_CHALLENGE: ByteArray = byteArrayOf(0x08, 0x04)

        /**
         * Service certificate of Google's production license server (license.google.com).
         * Not reachable directly, but many services proxy to it.
         */
        const val COMMON_PRIVACY_CERT: String =
            "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8yzdQPgZFuBTYdrjfQFEEQa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHleB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3rM3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/THhv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ7c4kcHCCaA1vZ8bYLErF8xNEkKdO7DevSy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmluZS5jb20SgAOuNHMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M4PxL/CCpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9qm9Nta/gr52u/DLpP3lnSq8x2/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeFHd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkPj89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98X/8z8QSQ+spbJTYLdgFenFoGq47gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ="

        /**
         * Service certificate of Google's staging license server (staging.google.com),
         * reachable without auth at https://cwip-shaka-proxy.appspot.com/no_auth
         */
        const val STAGING_PRIVACY_CERT: String =
            "CAUSxQUKvwIIAxIQKHA0VMAI9jYYredEPbbEyBiL5/mQBSKOAjCCAQoCggEBALUhErjQXQI/zF2V4sJRwcZJtBd82NK+7zVbsGdD3mYePSq8MYK3mUbVX9wI3+lUB4FemmJ0syKix/XgZ7tfCsB6idRa6pSyUW8HW2bvgR0NJuG5priU8rmFeWKqFxxPZmMNPkxgJxiJf14e+baq9a1Nuip+FBdt8TSh0xhbWiGKwFpMQfCB7/+Ao6BAxQsJu8dA7tzY8U1nWpGYD5LKfdxkagatrVEB90oOSYzAHwBTK6wheFC9kF6QkjZWt9/v70JIZ2fzPvYoPU9CVKtyWJOQvuVYCPHWaAgNRdiTwryi901goMDQoJk87wFgRwMzTDY4E5SGvJ2vJP1noH+a2UMCAwEAAToSc3RhZ2luZy5nb29nbGUuY29tEoADmD4wNSZ19AunFfwkm9rl1KxySaJmZSHkNlVzlSlyH/iA4KrvxeJ7yYDa6tq/P8OG0ISgLIJTeEjMdT/0l7ARp9qXeIoA4qprhM19ccB6SOv2FgLMpaPzIDCnKVww2pFbkdwYubyVk7jei7UPDe3BKTi46eA5zd4Y+oLoG7AyYw/pVdhaVmzhVDAL9tTBvRJpZjVrKH1lexjOY9Dv1F/FJp6X6rEctWPlVkOyb/SfEJwhAa/K81uDLyiPDZ1Flg4lnoX7XSTb0s+Cdkxd2b9yfvvpyGH4aTIfat4YkF9Nkvmm2mU224R1hx0WjocLsjA89wxul4TJPS3oRa2CYr5+DU4uSgdZzvgtEJ0lksckKfjAF0K64rPeytvDPD5fS69eFuy3Tq26/LfGcF96njtvOUA4P5xRFtICogySKe6WnCUZcYMDtQ0BMMM1LgawFNg4VA+KDCJ8ABHg9bOOTimO0sswHrRWSWX1XF15dXolCk65yEqz5lOfa2/fVomeopkU"

        private val ROOT_SIGNED_CERT_B64 =
            "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZyf7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfMqIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg17B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSCUNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0ay5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZVdA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2FRXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="
        private val ROOT_SIGNED_CERT =
            SignedDrmCertificate.ADAPTER.decode(ROOT_SIGNED_CERT_B64.decodeBase64()!!.toByteArray())
        private val ROOT_CERT = DrmCertificate.ADAPTER.decode(ROOT_SIGNED_CERT.drm_certificate!!)

        /**
         * Create a [Cdm] instance from a [Device].
         */
        fun fromDevice(device: Device): Cdm = Cdm(
            deviceType = device.type,
            clientId = device.clientId,
            privateKeyDer = device.privateKeyDer,
            systemId = device.systemId,
            securityLevel = device.securityLevel
        )
    }

    private suspend fun encryptClientId(
        client: ClientIdentification,
        serviceCert: DrmCertificate
    ): EncryptedClientIdentification {
        val privacyKey = randomBytes(16)
        val privacyIv = randomBytes(16)
        val padded = pkcs7Pad(client.encode())
        val encryptedClient = aesCbcEncryptNoPadding(privacyKey, privacyIv, padded)
        val encryptedPrivacyKey = rsaOaepEncrypt(
            serviceCert.public_key.orDecodeError("DrmCertificate.public_key").toByteArray(),
            privacyKey
        )
        return EncryptedClientIdentification(
            provider_id = serviceCert.provider_id,
            service_certificate_serial_number = serviceCert.serial_number,
            encrypted_client_id = encryptedClient.toByteString(),
            encrypted_client_id_iv = privacyIv.toByteString(),
            encrypted_privacy_key = encryptedPrivacyKey.toByteString()
        )
    }

    /**
     * Open a new session.
     * @return unique session identifier
     * @throws TooManySessionsException when [MAX_NUM_OF_SESSIONS] sessions are already open
     */
    suspend fun open(): ByteString = sessionsLock.withLock {
        // pywidevine compares with `>`, which lets a 17th session through; that is a bug,
        // and diverging from it is deliberate.
        if (sessions.size >= MAX_NUM_OF_SESSIONS)
            throw TooManySessionsException("Too many Sessions open ($MAX_NUM_OF_SESSIONS).")
        val s = Session(++sessionCounter)
        sessions[s.id] = s
        s.id
    }

    /**
     * Close and remove a session.
     * @param sessionId id returned by [open]
     * @throws InvalidSessionException if the id is unknown
     */
    suspend fun close(sessionId: ByteString) {
        sessionsLock.withLock {
            sessions.remove(sessionId)
                ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        }
    }

    /**
     * Set or clear a service certificate for a session.
     * When set and privacyMode is true in [getLicenseChallenge], the client_id will be
     * encrypted with this certificate as per Widevine privacy mode.
     * @param sessionId session id
     * @param certificate SignedMessage-wrapped SignedDrmCertificate bytes or raw SignedDrmCertificate bytes.
     *                    Pass null to clear and return the previous provider id.
     * @return provider id of the certificate if set, or previous provider id when clearing.
     * @throws InvalidSessionException if the session id is invalid
     * @throws DecodeException if parsing fails
     * @throws SignatureMismatchException if the certificate signature is invalid
     */
    suspend fun setServiceCertificate(sessionId: ByteString, certificate: ByteArray?): String? {
        val s = session(sessionId)
        if (certificate == null) {
            val prev = s.lock.withLock {
                s.serviceCertificate.also { s.serviceCertificate = null }
            }
            return prev?.let {
                DrmCertificate.ADAPTER.decode(
                    it.drm_certificate.orDecodeError("SignedDrmCertificate.drm_certificate")
                ).provider_id
            }
        }
        // try parse SignedMessage wrapping SignedDrmCertificate, else direct SignedDrmCertificate
        val signedOrRaw = try {
            SignedMessage.ADAPTER.decode(certificate)
        } catch (_: Throwable) {
            null
        }
        val signedCert = if (signedOrRaw != null && signedOrRaw.msg != null) {
            try {
                SignedDrmCertificate.ADAPTER.decode(signedOrRaw.msg)
            } catch (e: Throwable) {
                throw DecodeException(
                    "Could not parse certificate as SignedDrmCertificate in SignedMessage, $e"
                )
            }
        } else {
            try {
                SignedDrmCertificate.ADAPTER.decode(certificate)
            } catch (e: Throwable) {
                throw DecodeException(
                    "Could not parse certificate as SignedDrmCertificate, $e"
                )
            }
        }
        val certBytes = signedCert.drm_certificate.orDecodeError("SignedDrmCertificate.drm_certificate")
        val certSignature = signedCert.signature.orDecodeError("SignedDrmCertificate.signature")
        val drmCert = try {
            DrmCertificate.ADAPTER.decode(certBytes)
        } catch (e: Throwable) {
            throw DecodeException(
                "Could not parse signed certificate's message as a DrmCertificate, $e"
            )
        }

        // Verify signature using root cert public key
        val ok = rsaPssVerifySha1(
            ROOT_CERT.public_key!!.toByteArray(),
            certBytes.toByteArray(),
            certSignature.toByteArray()
        )
        if (!ok) throw SignatureMismatchException("Signature Mismatch on SignedDrmCertificate, rejecting certificate")

        s.lock.withLock { s.serviceCertificate = signedCert }
        return drmCert.provider_id
    }

    /**
     * Overload of [setServiceCertificate] accepting a Base64-encoded certificate string.
     * Pass null to clear the currently set certificate.
     */
    suspend fun setServiceCertificate(sessionId: ByteString, certificateBase64: String?): String? {
        val bytes = certificateBase64?.decodeBase64()?.toByteArray()
            ?: return setServiceCertificate(sessionId, null as ByteArray?)
        return setServiceCertificate(sessionId, bytes)
    }

    /**
     * Get the currently configured service certificate for a session, if any.
     */
    suspend fun getServiceCertificate(sessionId: ByteString): SignedDrmCertificate? {
        val s = session(sessionId)
        return s.lock.withLock { s.serviceCertificate }
    }

    /**
     * Build and sign a Widevine license request for the provided [pssh].
     * Stores internal request context needed to later [parseLicense] for this session.
     * @param sessionId session id from [open]
     * @param pssh parsed or raw init data holder
     * @param licenseType type of license to request (e.g., STREAMING)
     * @param privacyMode if true and a service certificate is set, send encrypted client id
     * @param requestType NEW for a first request; RENEWAL or RELEASE reference the license
     *   already parsed for this session rather than the content
     * @return the serialized SignedMessage(LICENSE_REQUEST)
     * @throws InvalidSessionException if the session id is invalid
     * @throws InvalidInitDataException if pssh init data is empty
     * @throws InvalidContextException if a RENEWAL or RELEASE is requested before a license
     *   has been parsed for this session
     * @throws ValueException if a RENEWAL is requested but the policy forbids it
     */
    suspend fun getLicenseChallenge(
        sessionId: ByteString,
        pssh: PSSH,
        licenseType: LicenseType = LicenseType.STREAMING,
        privacyMode: Boolean = true,
        requestType: LicenseRequest.RequestType = LicenseRequest.RequestType.NEW
    ): ByteArray {
        val s = session(sessionId)
        val init = pssh.initData
        if (init.isEmpty()) throw InvalidInitDataException("A pssh must be provided.")

        val requestId: ByteString = buildRequestId(s.number)
        val requestTime = System.currentTimeMillis() / 1000

        val serviceCertificate = s.lock.withLock { s.serviceCertificate }
        val encryptedClientId = if (serviceCertificate != null && privacyMode) {
            val drm = DrmCertificate.ADAPTER.decode(
                serviceCertificate.drm_certificate.orDecodeError("SignedDrmCertificate.drm_certificate")
            )
            encryptClientId(clientId, drm)
        } else null

        val contentId = when (requestType) {
            LicenseRequest.RequestType.NEW -> LicenseRequest.ContentIdentification(
                widevine_pssh_data = LicenseRequest.ContentIdentification.WidevinePsshData(
                    pssh_data = listOf(init.toByteString()),
                    license_type = licenseType,
                    request_id = requestId
                )
            )

            // RENEWAL and RELEASE identify the license already held, not the content.
            else -> LicenseRequest.ContentIdentification(
                existing_license = LicenseRequest.ContentIdentification.ExistingLicense(
                    license_id = existingLicenseId(s, requestType)
                )
            )
        }

        val lr = LicenseRequest(
            client_id = if (encryptedClientId == null) clientId else null,
            content_id = contentId,
            type = requestType,
            request_time = requestTime,
            protocol_version = ProtocolVersion.VERSION_2_1,
            key_control_nonce = randomInt(1, Int.MAX_VALUE),
            encrypted_client_id = encryptedClientId
        )

        Logger.d("ktvine") {
            "Generating License Request - " +
            "Session ID: $sessionId, " +
            "Request ID: $requestId, " +
            "Request Time: $requestTime, " +
            "License Type: $licenseType, " +
            "Privacy Mode: $privacyMode, " +
            "Encrypted Client ID: ${encryptedClientId != null}"
        }

        val encodedLr = lr.encode()
        // Signed with the device key for every request type: license_protocol.proto says the
        // algorithm for a request is "determined by the certificate contained in the request",
        // and the session-key HMAC applies to responses. Renewals are untested against a real
        // server, so this is deliberately not switched to macKeyClient.
        val signature = rsaPssSignSha1(privateKeyDer, encodedLr)

        val sm = SignedMessage(
            type = SignedMessage.MessageType.LICENSE_REQUEST,
            msg = encodedLr.toByteString(),
            signature = signature.toByteString()
        )

        val (encCtx, macCtx) = deriveContext(encodedLr)
        s.lock.withLock { s.context[requestId] = encCtx to macCtx }

        return sm.encode()
    }

    /**
     * Parse and verify a Widevine license response for the provided [sessionId].
     * This consumes the previously stored request context created by [getLicenseChallenge],
     * decrypts contained keys and stores them on the session.
     * @throws InvalidSessionException if the session is unknown
     * @throws InvalidContextException if no license request was made for this session
     * @throws InvalidLicenseMessageException if the message is empty, is an ERROR_RESPONSE,
     *   or is not a LICENSE
     * @throws DecodeException if parsing fails
     * @throws SignatureMismatchException if MAC verification fails
     */
    suspend fun parseLicense(sessionId: ByteString, licenseMessage: ByteArray) {
        val s = session(sessionId)
        if (licenseMessage.isEmpty()) throw InvalidLicenseMessageException("Cannot parse an empty license_message")

        val sm = try {
            SignedMessage.ADAPTER.decode(licenseMessage)
        } catch (e: Throwable) {
            throw DecodeException(
                "Could not parse license_message as a SignedMessage, $e"
            )
        }
        if (sm.type == SignedMessage.MessageType.ERROR_RESPONSE) {
            // Neither this vendored schema nor pywidevine's defines LicenseError, so the
            // payload is reported verbatim for the caller to decode.
            val detail = sm.msg?.toByteArray()?.toHexString() ?: "<empty>"
            val version = sm.service_version_info?.let { " (service ${it.license_service_version})" } ?: ""
            throw InvalidLicenseMessageException(
                "License server returned an ERROR_RESPONSE$version, payload: $detail"
            )
        }
        if (sm.type != SignedMessage.MessageType.LICENSE)
            throw InvalidLicenseMessageException("Expecting a LICENSE message, not a '${sm.type}' message.")

        val msg = sm.msg.orDecodeError("SignedMessage.msg")
        val license = try {
            License.ADAPTER.decode(msg)
        } catch (e: Throwable) {
            throw DecodeException(
                "Could not parse license_message's message as a License, $e"
            )
        }

        // Expect a matching request context from prior getLicenseChallenge
        val requestId = license.id?.request_id
            ?: throw InvalidLicenseMessageException("License is missing its id.request_id")
        val (encCtx, macCtx) = s.lock.withLock { s.context[requestId] }
            ?: throw InvalidContextException("Cannot parse a license message without first making a license request")

        // Unwrap session key and derive enc/mac keys
        val sessionKey = rsaOaepDecrypt(
            privateKeyDer,
            sm.session_key.orDecodeError("SignedMessage.session_key").toByteArray()
        )
        val (encKey, macKeyServer, macKeyClient) = deriveKeys(encCtx, macCtx, sessionKey)

        // Compute HMAC over optional oemcrypto_core_message prefix + msg, as per OEMCrypto v16+
        val core = sm.oemcrypto_core_message?.toByteArray() ?: ByteArray(0)
        val computedSig = hmacSha256(macKeyServer, core + msg.toByteArray())
        if (!constantTimeEquals(computedSig, sm.signature.orDecodeError("SignedMessage.signature").toByteArray()))
            throw SignatureMismatchException("Signature Mismatch on License Message, rejecting license")

        // Load Keys from license
        val parsed = mutableListOf<Key>()
        for (kc in license.key) {
            try {
                parsed.add(Key.fromContainer(kc, encKey))
            } catch (error: Throwable) {
                // ignore malformed keys
                Logger.e("ktvine") {
                    "Error parsing key container: ${error.message}"
                }
                error.printStackTrace()
            }
        }

        s.lock.withLock {
            s.keys.clear()
            s.keys.addAll(parsed)
            s.license = license
            s.macKeyClient = macKeyClient
            // drop used context for this request
            s.context.remove(requestId)
        }
    }

    /**
     * The `LicenseIdentification` of the license already held by this session.
     *
     * @throws InvalidContextException if no license has been parsed for the session
     * @throws ValueException if the license's policy does not permit renewal
     */
    private suspend fun existingLicenseId(
        s: Session,
        requestType: LicenseRequest.RequestType
    ): LicenseIdentification {
        val license = s.lock.withLock { s.license }
            ?: throw InvalidContextException(
                "A $requestType request needs a parsed license; call parseLicense first."
            )

        if (requestType == LicenseRequest.RequestType.RENEWAL && license.policy?.can_renew != true) {
            throw ValueException("This license's policy does not allow renewal.")
        }

        return license.id.orDecodeError("License.id")
    }

    /**
     * OEMCrypto on Android emits the request id as an AES-CTR counter block stored as a
     * 32-character uppercase hex string, e.g. `A0DCE548000000000500000000000000`. Some
     * services fingerprint that shape, so it is worth reproducing.
     */
    private fun buildRequestId(sessionNumber: Int): ByteString {
        if (deviceType != DeviceTypes.ANDROID) return randomBytes(16).toByteString()

        val counter = ByteArray(8) { i -> (sessionNumber.toLong() ushr (8 * i)).toByte() }
        val block = randomBytes(4) + ByteArray(4) + counter
        // 16 bytes of data, but 32 bytes on the wire.
        return block.toHexString().uppercase().encodeToByteArray().toByteString()
    }

    private fun deriveContext(message: ByteArray): Pair<ByteArray, ByteArray> {
        fun encCtx(msg: ByteArray): ByteArray {
            val label = "ENCRYPTION".encodeToByteArray()
            val keySize = 128
            return label + byteArrayOf(0) + msg + byteArrayOf(
                (keySize ushr 24).toByte(),
                (keySize ushr 16).toByte(),
                (keySize ushr 8).toByte(),
                keySize.toByte()
            )
        }

        fun macCtx(msg: ByteArray): ByteArray {
            val label = "AUTHENTICATION".encodeToByteArray()
            val keySize = 512
            return label + byteArrayOf(0) + msg + byteArrayOf(
                (keySize ushr 24).toByte(),
                (keySize ushr 16).toByte(),
                (keySize ushr 8).toByte(),
                keySize.toByte()
            )
        }
        return encCtx(message) to macCtx(message)
    }

    private suspend fun deriveKeys(
        encContext: ByteArray,
        macContext: ByteArray,
        key: ByteArray
    ): Triple<ByteArray, ByteArray, ByteArray> {
        suspend fun derive(context: ByteArray, counter: Int): ByteArray {
            return aesCmac(key, byteArrayOf(counter.toByte()) + context)
        }

        val encKey = derive( encContext, 1)
        val macKeyServer = derive(macContext, 1) + derive( macContext, 2)
        val macKeyClient = derive( macContext, 3) + derive(macContext, 4)
        return Triple(encKey, macKeyServer, macKeyClient)
    }

    /**
     * The license parsed by the most recent [parseLicense] call for this session, or `null`
     * when none has been parsed.
     *
     * Read `policy` for `can_persist`, `can_renew`, `rental_duration_seconds`,
     * `renewal_server_url` and friends; offline and download flows need those.
     */
    suspend fun getLicense(sessionId: ByteString): License? {
        val s = session(sessionId)
        return s.lock.withLock { s.license }
    }

    /**
     * Convenience to get decrypted keys for the session. Optionally filter by [License.KeyContainer.KeyType].
     */
    suspend fun getKeys(sessionId: ByteString, type: License.KeyContainer.KeyType? = null): List<Key> {
        val s = session(sessionId)
        return s.lock.withLock { s.keys.filter { type == null || it.type == type.name } }
    }
}
