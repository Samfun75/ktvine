package org.samfun.ktvine.cdm

import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.utils.InvalidInitDataException
import org.samfun.ktvine.utils.InvalidLicenseTypeException
import org.samfun.ktvine.utils.InvalidSessionException
import org.samfun.ktvine.core.Key
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.core.Session
import org.samfun.ktvine.utils.SignatureMismatchException
import org.samfun.ktvine.utils.TooManySessionsException
import org.samfun.ktvine.crypto.*
import org.samfun.ktvine.proto.*
import java.util.UUID
import kotlin.random.Random

class Cdm(
    private val deviceType: DeviceTypes,
    private val clientId: ClientIdentification,
    private val privateKeyDer: ByteArray
) {
    private val sessions = linkedMapOf<ByteString, Session>()

    companion object {
        val uuid: UUID = UUID.nameUUIDFromBytes(
            byteArrayOf(
                0xED.toByte(), 0xEF.toByte(), 0x8B.toByte(), 0xA9.toByte(), 0x79, 0xD6.toByte(), 0x4A, 0xCE.toByte(),
                0xA3.toByte(), 0xC8.toByte(), 0x27, 0xDC.toByte(), 0xD5.toByte(), 0x1D, 0x21, 0xED.toByte()
            )
        )
        val urn = "urn:uuid:$uuid"

        private val ROOT_SIGNED_CERT_B64 =
            "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZyf7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfMqIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg17B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSCUNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0ay5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZVdA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2FRXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="
        private val ROOT_SIGNED_CERT =
            SignedDrmCertificate.ADAPTER.decode(ROOT_SIGNED_CERT_B64.decodeBase64()!!.toByteArray())
        private val ROOT_CERT = DrmCertificate.ADAPTER.decode(ROOT_SIGNED_CERT.drm_certificate!!)

        fun fromDevice(device: Device): Cdm = Cdm(
            deviceType = device.type,
            clientId = device.clientId,
            privateKeyDer = device.privateKeyDer
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
        val encryptedPrivacyKey = rsaOaepEncrypt(serviceCert.public_key!!.toByteArray(), privacyKey)
        return EncryptedClientIdentification(
            provider_id = serviceCert.provider_id,
            service_certificate_serial_number = serviceCert.serial_number,
            encrypted_client_id = encryptedClient.toByteString(),
            encrypted_client_id_iv = privacyIv.toByteString(),
            encrypted_privacy_key = encryptedPrivacyKey.toByteString()
        )
    }

    fun open(): ByteString {
        if (sessions.size > 16) throw TooManySessionsException("Too many Sessions open (16).")
        val s = Session(sessions.size + 1)
        sessions[s.id] = s
        return s.id
    }

    fun close(sessionId: ByteString) {
        sessions.remove(sessionId) ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
    }

    suspend fun setServiceCertificate(sessionId: ByteString, certificate: ByteArray?): String? {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        if (certificate == null) {
            val prev = s.serviceCertificate
            s.serviceCertificate = null
            return prev?.let { DrmCertificate.ADAPTER.decode(it.drm_certificate!!).provider_id }
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
        val drmCert = try {
            DrmCertificate.ADAPTER.decode(signedCert.drm_certificate!!)
        } catch (e: Throwable) {
            throw DecodeException(
                "Could not parse signed certificate's message as a DrmCertificate, $e"
            )
        }

        // Verify signature using root cert public key
        val ok = rsaPssVerifySha1(
            ROOT_CERT.public_key!!.toByteArray(),
            signedCert.drm_certificate.toByteArray(),
            signedCert.signature!!.toByteArray()
        )
        if (!ok) throw SignatureMismatchException("Signature Mismatch on SignedDrmCertificate, rejecting certificate")

        s.serviceCertificate = signedCert
        return drmCert.provider_id
    }

    // Overload: accept Base64 certificate string
    suspend fun setServiceCertificate(sessionId: ByteString, certificateBase64: String?): String? {
        val bytes = certificateBase64?.decodeBase64()?.toByteArray()
            ?: return setServiceCertificate(sessionId, null as ByteArray?)
        return setServiceCertificate(sessionId, bytes)
    }

    fun getServiceCertificate(sessionId: ByteString): SignedDrmCertificate? {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        return s.serviceCertificate
    }

    suspend fun getLicenseChallenge(
        sessionId: ByteString,
        pssh: PSSH,
        licenseType: LicenseType = LicenseType.STREAMING,
        privacyMode: Boolean = true
    ): ByteArray {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        val init = pssh.initData
        if (init.isEmpty()) throw InvalidInitDataException("A pssh must be provided.")

        val requestId: ByteString = if (deviceType == DeviceTypes.ANDROID) {
            // emulate OEMCrypto counter-like request id (upper hex)
            val counter = s.number
            val prefix = randomBytes(4) + ByteArray(4) { 0x00 }
            val buf = prefix + ByteArray(8).apply {
                var v = counter
                for (i in 0 until 8) {
                    this[i] = (v and 0xFF).toByte(); v = v ushr 8
                }
            }
            buf.joinToString(separator = "") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }.uppercase()
                .toByteArray().toByteString()
        } else {
            randomBytes(16).toByteString()
        }

        val encryptedClientId = if (s.serviceCertificate != null && privacyMode) {
            val drm = DrmCertificate.ADAPTER.decode(s.serviceCertificate!!.drm_certificate!!)
            encryptClientId(clientId, drm)
        } else null

        val lr = LicenseRequest(
            client_id = if (encryptedClientId == null) clientId else null,
            content_id = LicenseRequest.ContentIdentification(
                widevine_pssh_data = LicenseRequest.ContentIdentification.WidevinePsshData(
                    pssh_data = listOf(init.toByteString()),
                    license_type = licenseType,
                    request_id = requestId
                )
            ),
            type = LicenseRequest.RequestType.NEW,
            request_time = System.currentTimeMillis() / 1000,
            protocol_version = ProtocolVersion.VERSION_2_1,
            key_control_nonce = Random.nextInt(),
            encrypted_client_id = encryptedClientId
        )

        val encodedLr = lr.encode()
        val signature = rsaPssSignSha1(privateKeyDer, encodedLr)

        val sm = SignedMessage(
            type = SignedMessage.MessageType.LICENSE_REQUEST,
            msg = encodedLr.toByteString(),
            signature = signature.toByteString()
        )

        val (encCtx, macCtx) = deriveContext(encodedLr)
        s.context[requestId] = encCtx to macCtx

        return sm.encode()
    }

    suspend fun parseLicense(sessionId: ByteString, licenseMessage: ByteArray) {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        if (licenseMessage.isEmpty()) throw InvalidLicenseTypeException("Cannot parse an empty license_message")

        val sm = try {
            SignedMessage.ADAPTER.decode(licenseMessage)
        } catch (e: Throwable) {
            throw DecodeException(
                "Could not parse license_message as a SignedMessage, $e"
            )
        }
        if (sm.type != SignedMessage.MessageType.LICENSE) throw InvalidLicenseTypeException("Expecting a LICENSE message, not a '${sm.type}' message.")

        val license = try {
            License.ADAPTER.decode(sm.msg!!)
        } catch (e: Throwable) {
            throw DecodeException(
                "Could not parse license_message's message as a License, $e"
            )
        }

        // Expect a matching request context from prior getLicenseChallenge
        val requestId = license.id?.request_id ?: throw InvalidLicenseTypeException("License is missing request_id")
        val (encCtx, macCtx) = s.context[requestId]
            ?: throw InvalidSessionException("Cannot parse a license message without first making a license request")

        // Unwrap session key and derive enc/mac keys
        val sessionKey = rsaOaepDecrypt(privateKeyDer, sm.session_key!!.toByteArray())
        val (encKey, macKeyServer, _) = deriveKeys(encCtx, macCtx, sessionKey)

        // Compute HMAC over optional oemcrypto_core_message prefix + msg, as per OEMCrypto v16+
        val core = sm.oemcrypto_core_message?.toByteArray() ?: ByteArray(0)
        val computedSig = hmacSha256(macKeyServer, core + sm.msg.toByteArray())
        if (!computedSig.contentEquals(sm.signature!!.toByteArray())) throw SignatureMismatchException("Signature Mismatch on License Message, rejecting license")

        // Load Keys from license
        s.keys.clear()
        for (kc in license.key) {
            try {
                s.keys.add(Key.fromContainer(kc, encKey))
            } catch (error: Throwable) {
                // ignore malformed keys
                println("[ktvine] Error parsing key ${error.localizedMessage}")
            }
        }
        // drop used context for this request
        s.context.remove(requestId)
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

    // Convenience to get loaded keys, optionally filtered by License Key Type
    fun getKeys(sessionId: ByteString, type: License.KeyContainer.KeyType? = null): List<Key> {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        return s.keys.filter { type == null || it.type == type.name }
    }
}
