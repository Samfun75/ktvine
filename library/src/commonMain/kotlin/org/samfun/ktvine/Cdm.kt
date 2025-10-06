package org.samfun.ktvine

import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.crypto.*
import org.samfun.ktvine.proto.*
import java.util.UUID

class Cdm(
    val deviceType: DeviceTypes,
    val systemId: Int,
    val securityLevel: Int,
    private val clientId: ClientIdentification,
    private val privateKeyDer: ByteArray
) {
    private val sessions = linkedMapOf<ByteString, Session>()

    companion object {
        val uuid: UUID = UUID.nameUUIDFromBytes(byteArrayOf(
            0xED.toByte(), 0xEF.toByte(), 0x8B.toByte(), 0xA9.toByte(), 0x79, 0xD6.toByte(), 0x4A, 0xCE.toByte(),
            0xA3.toByte(), 0xC8.toByte(), 0x27, 0xDC.toByte(), 0xD5.toByte(), 0x1D, 0x21, 0xED.toByte()
        ))
        val urn = "urn:uuid:$uuid"
        val key_format = urn

        // Root certificate used to verify service/privacy certificates
        private val ROOT_SIGNED_CERT_B64 = "CpwDCAASAQAY3ZSIiwUijgMwggGKAoIBgQC0/jnDZZAD2zwRlwnoaM3yw16b8udNI7EQ24dl39z7nzWgVwNTTPZtNX2meNuzNtI/nECplSZyf7i+Zt/FIZh4FRZoXS9GDkPLioQ5q/uwNYAivjQji6tTW3LsS7VIaVM+R1/9Cf2ndhOPD5LWTN+udqm62SIQqZ1xRdbX4RklhZxTmpfrhNfMqIiCIHAmIP1+QFAn4iWTb7w+cqD6wb0ptE2CXMG0y5xyfrDpihc+GWP8/YJIK7eyM7l97Eu6iR8nuJuISISqGJIOZfXIbBH/azbkdDTKjDOx+biOtOYS4AKYeVJeRTP/Edzrw1O6fGAaET0A+9K3qjD6T15Id1sX3HXvb9IZbdy+f7B4j9yCYEy/5CkGXmmMOROtFCXtGbLynwGCDVZEiMg17B8RsyTgWQ035Ec86kt/lzEcgXyUikx9aBWE/6UI/Rjn5yvkRycSEbgj7FiTPKwS0ohtQT3F/hzcufjUUT4H5QNvpxLoEve1zqaWVT94tGSCUNIzX5ECAwEAARKAA1jx1k0ECXvf1+9dOwI5F/oUNnVKOGeFVxKnFO41FtU9v0KG9mkAds2T9Hyy355EzUzUrgkYU0Qy7OBhG+XaE9NVxd0ay5AeflvG6Q8in76FAv6QMcxrA4S9IsRV+vXyCM1lQVjofSnaBFiC9TdpvPNaV4QXezKHcLKwdpyywxXRESYqI3WZPrl3IjINvBoZwdVlkHZVdA8OaU1fTY8Zr9/WFjGUqJJfT7x6Mfiujq0zt+kw0IwKimyDNfiKgbL+HIisKmbF/73mF9BiC9yKRfewPlrIHkokL2yl4xyIFIPVxe9enz2FRXPia1BSV0z7kmxmdYrWDRuu8+yvUSIDXQouY5OcCwEgqKmELhfKrnPsIht5rvagcizfB0fbiIYwFHghESKIrNdUdPnzJsKlVshWTwApHQh7evuVicPumFSePGuUBRMS9nG5qxPDDJtGCHs9Mmpoyh6ckGLF7RC5HxclzpC5bc3ERvWjYhN0AqdipPpV2d7PouaAdFUGSdUCDA=="
        private val ROOT_SIGNED_CERT = SignedDrmCertificate.ADAPTER.decode(ROOT_SIGNED_CERT_B64.decodeBase64()!!.toByteArray())
        private val ROOT_CERT = DrmCertificate.ADAPTER.decode(ROOT_SIGNED_CERT.drm_certificate!!)

        // Common and staging privacy certificates as base64 strings for convenience
        val common_privacy_cert_b64 = "CAUSxwUKwQIIAxIQFwW5F8wSBIaLBjM6L3cqjBiCtIKSBSKOAjCCAQoCggEBAJntWzsyfateJO/DtiqVtZhSCtW8yzdQPgZFuBTYdrjfQFEEQa2M462xG7iMTnJaXkqeB5UpHVhYQCOn4a8OOKkSeTkwCGELbxWMh4x+Ib/7/up34QGeHleB6KRfRiY9FOYOgFioYHrc4E+shFexN6jWfM3rM3BdmDoh+07svUoQykdJDKR+ql1DghjduvHK3jOS8T1v+2RC/THhv0CwxgTRxLpMlSCkv5fuvWCSmvzu9Vu69WTi0Ods18Vcc6CCuZYSC4NZ7c4kcHCCaA1vZ8bYLErF8xNEkKdO7DevSy8BDFnoKEPiWC8La59dsPxebt9k+9MItHEbzxJQAZyfWgkCAwEAAToUbGljZW5zZS53aWRldmluZS5jb20SgAOuNHMUtag1KX8nE4j7e7jLUnfSSYI83dHaMLkzOVEes8y96gS5RLknwSE0bv296snUE5F+bsF2oQQ4RgpQO8GVK5uk5M4PxL/CCpgIqq9L/NGcHc/N9XTMrCjRtBBBbPneiAQwHL2zNMr80NQJeEI6ZC5UYT3wr8+WykqSSdhV5Cs6cD7xdn9qm9Nta/gr52u/DLpP3lnSq8x2/rZCR7hcQx+8pSJmthn8NpeVQ/ypy727+voOGlXnVaPHvOZV+WRvWCq5z3CqCLl5+Gf2Ogsrf9s2LFvE7NVV2FvKqcWTw4PIV9Sdqrd+QLeFHd/SSZiAjjWyWOddeOrAyhb3BHMEwg2T7eTo/xxvF+YkPj89qPwXCYcOxF+6gjomPwzvofcJOxkJkoMmMzcFBDopvab5tDQsyN9UPLGhGC98X/8z8QSQ+spbJTYLdgFenFoGq47gLwDS6NWYYQSqzE3Udf2W7pzk4ybyG4PHBYV3s4cyzdq8amvtE/sNSdOKReuHpfQ="
        val staging_privacy_cert_b64 = "CAUSxQUKvwIIAxIQKHA0VMAI9jYYredEPbbEyBiL5/mQBSKOAjCCAQoCggEBALUhErjQXQI/zF2V4sJRwcZJtBd82NK+7zVbsGdD3mYePSq8MYK3mUbVX9wI3+lUB4FemmJ0syKix/XgZ7tfCsB6idRa6pSyUW8HW2bvgR0NJuG5priU8rmFeWKqFxxPZmMNPkxgJxiJf14e+baq9a1Nuip+FBdt8TSh0xhbWiGKwFpMQfCB7/+Ao6BAxQsJu8dA7tzY8U1nWpGYD5LKfdxkagatrVEB90oOSYzAHwBTK6wheFC9kF6QkjZWt9/v70JIZ2fzPvYoPU9CVKtyWJOQvuVYCPHWaAgNRdiTwryi901goMDQoJk87wFgRwMzTDY4E5SGvJ2vJP1noH+a2UMCAwEAAToSc3RhZ2luZy5nb29nbGUuY29tEoADmD4wNSZ19AunFfwkm9rl1KxySaJmZSHkNlVzlSlyH/iA4KrvxeJ7yYDa6tq/P8OG0ISgLIJTeEjMdT/0l7ARp9qXeIoA4qprhM19ccB6SOv2FgLMpaPzIDCnKVww2pFbkdwYubyVk7jei7UPDe3BKTi46eA5zd4Y+oLoG7AyYw/pVdhaVmzhVDAL9tTBvRJpZjVrKH1lexjOY9Dv1F/FJp6X6rEctWPlVkOyb/SfEJwhAa/K81uDLyiPDZ1Flg4lnoX7XSTb0s+Cdkxd2b9yfvvpyGH4aTIfat4YkF9Nkvmm2mU224R1hx0WjocLsjA89wxul4TJPS3oRa2CYr5+DU4uSgdZzvgtEJ0lksckKfjAF0K64rPeytvDPD5fS69eFuy3Tq26/LfGcF96njtvOUA4P5xRFtICogySKe6WnCUZcYMDtQ0BMMM1LgawFNg4VA+KDCJ8ABHg9bOOTimO0sswHrRWSWX1XF15dXolCk65yEqz5lOfa2/fVomeopkU"

        fun fromDevice(device: Device): Cdm = Cdm(
            deviceType = device.type,
            systemId = device.systemId,
            securityLevel = device.securityLevel,
            clientId = device.clientId,
            privateKeyDer = device.privateKeyDer
        )
    }

    fun open(): ByteString {
        if (sessions.size > 16) throw TooManySessionsException("Too many Sessions open (16).")
        val s = Session(sessions.size + 1)
        sessions[s.id] = s
        return s.id
    }

    fun close(sessionId: ByteString) {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        sessions.remove(sessionId)
    }

    fun setServiceCertificate(sessionId: ByteString, certificate: ByteArray?): String? {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        if (certificate == null) {
            val prev = s.serviceCertificate
            s.serviceCertificate = null
            return prev?.let { DrmCertificate.ADAPTER.decode(it.drm_certificate!!).provider_id }
        }
        // try parse SignedMessage wrapping SignedDrmCertificate, else direct SignedDrmCertificate
        val signedOrRaw = try { SignedMessage.ADAPTER.decode(certificate) } catch (_: Throwable) { null }
        val signedCert = if (signedOrRaw != null && signedOrRaw.msg != null) {
            try { SignedDrmCertificate.ADAPTER.decode(signedOrRaw.msg!!) } catch (e: Throwable) { throw DecodeException("Could not parse certificate as SignedDrmCertificate in SignedMessage, $e") }
        } else {
            try { SignedDrmCertificate.ADAPTER.decode(certificate) } catch (e: Throwable) { throw DecodeException("Could not parse certificate as SignedDrmCertificate, $e") }
        }
        val drmCert = try { DrmCertificate.ADAPTER.decode(signedCert.drm_certificate!!) } catch (e: Throwable) { throw DecodeException("Could not parse signed certificate's message as a DrmCertificate, $e") }

        // Verify signature using root cert public key
        val ok = rsaPssVerifySha1(ROOT_CERT.public_key!!.toByteArray(), signedCert.drm_certificate!!.toByteArray(), signedCert.signature!!.toByteArray())
        if (!ok) throw SignatureMismatchException("Signature Mismatch on SignedDrmCertificate, rejecting certificate")

        s.serviceCertificate = signedCert
        return drmCert.provider_id
    }

    fun getServiceCertificate(sessionId: ByteString): SignedDrmCertificate? {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        return s.serviceCertificate
    }

    fun getLicenseChallenge(
        sessionId: ByteString,
        pssh: PSSH,
        licenseType: LicenseType = LicenseType.STREAMING,
        privacyMode: Boolean = true
    ): ByteArray {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        val init = pssh.init_data
        if (init.isEmpty()) throw InvalidInitDataException("A pssh must be provided.")

        val requestId: ByteString = if (deviceType == DeviceTypes.ANDROID) {
            // emulate OEMCrypto counter-like request id (upper hex)
            val counter = s.number
            val prefix = randomBytes(4) + ByteArray(4) { 0x00 }
            val buf = prefix + ByteArray(8).apply {
                var v = counter
                for (i in 0 until 8) { this[i] = (v and 0xFF).toByte(); v = v ushr 8 }
            }
            buf.joinToString(separator = "") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }.uppercase().encodeToByteArray().toByteString()
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
            request_time = (System.currentTimeMillis() / 1000),
            protocol_version = ProtocolVersion.VERSION_2_1,
            key_control_nonce = (randomBytes(4).let { ((it[0].toInt() and 0xFF) shl 24) or ((it[1].toInt() and 0xFF) shl 16) or ((it[2].toInt() and 0xFF) shl 8) or (it[3].toInt() and 0xFF) }),
            encrypted_client_id = encryptedClientId
        ).encode()

        val signature = rsaPssSignSha1(privateKeyDer, lr)

        val sm = SignedMessage(
            type = SignedMessage.MessageType.LICENSE_REQUEST,
            msg = lr.toByteString(),
            signature = signature.toByteString()
        ).encode()

        val (encCtx, macCtx) = deriveContext(lr)
        s.context[requestId] = encCtx to macCtx

        return sm
    }

    fun parseLicense(sessionId: ByteString, licenseMessage: ByteArray) {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        if (licenseMessage.isEmpty()) throw InvalidLicenseTypeException("Cannot parse an empty license_message")

        val sm = try { SignedMessage.ADAPTER.decode(licenseMessage) } catch (e: Throwable) { throw DecodeException("Could not parse license_message as a SignedMessage, $e") }
        if (sm.type != SignedMessage.MessageType.LICENSE) throw InvalidLicenseTypeException("Expecting a LICENSE message, not a '${'$'}{sm.type}' message.")

        val lic = License.ADAPTER.decode(sm.msg!!)
        val ctx = s.context[lic.id!!.request_id] ?: throw InvalidSessionException("Cannot parse a license message without first making a license request")

        val (encKey, macKeyServer, _) = deriveKeys(ctx.first, ctx.second, rsaOaepDecryptSha1(privateKeyDer, sm.session_key!!.toByteArray()))

        val computedSig = hmacSha256(macKeyServer, (sm.oemcrypto_core_message ?: ByteString.EMPTY).toByteArray() + sm.msg.toByteArray())
        if (!computedSig.contentEquals(sm.signature!!.toByteArray())) throw SignatureMismatchException("Signature Mismatch on License Message, rejecting license")

        s.keys.clear()
        s.keys.addAll(lic.key.map { Key.fromContainer(it, encKey) })

        s.context.remove(lic.id.request_id)
    }

    fun getKeys(sessionId: ByteString, type: License.KeyContainer.KeyType? = null): List<Key> {
        val s = sessions[sessionId] ?: throw InvalidSessionException("Session identifier $sessionId is invalid.")
        return s.keys.filter { type == null || it.type == type.name }
    }

    private fun encryptClientId(client: ClientIdentification, serviceCert: DrmCertificate): EncryptedClientIdentification {
        val privacyKey = randomBytes(16)
        val privacyIv = randomBytes(16)
        val padded = pkcs7Pad(client.encode())
        val encryptedClient = aesCbcEncryptNoPadding(privacyKey, privacyIv, padded)
        val encryptedPrivacyKey = rsaOaepEncryptSha1(serviceCert.public_key!!.toByteArray(), privacyKey)
        return EncryptedClientIdentification(
            provider_id = serviceCert.provider_id,
            service_certificate_serial_number = serviceCert.serial_number,
            encrypted_client_id = encryptedClient.toByteString(),
            encrypted_client_id_iv = privacyIv.toByteString(),
            encrypted_privacy_key = encryptedPrivacyKey.toByteString()
        )
    }

    private fun deriveContext(message: ByteArray): Pair<ByteArray, ByteArray> {
        fun encCtx(msg: ByteArray): ByteArray {
            val label = "ENCRYPTION".encodeToByteArray()
            val keySize = 16 * 8
            return label + byteArrayOf(0) + msg + byteArrayOf((keySize ushr 24).toByte(), (keySize ushr 16).toByte(), (keySize ushr 8).toByte(), keySize.toByte())
        }
        fun macCtx(msg: ByteArray): ByteArray {
            val label = "AUTHENTICATION".encodeToByteArray()
            val keySize = 32 * 8 * 2
            return label + byteArrayOf(0) + msg + byteArrayOf((keySize ushr 24).toByte(), (keySize ushr 16).toByte(), (keySize ushr 8).toByte(), keySize.toByte())
        }
        return encCtx(message) to macCtx(message)
    }

    private fun deriveKeys(encContext: ByteArray, macContext: ByteArray, key: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        fun derive(sessionKey: ByteArray, context: ByteArray, counter: Int): ByteArray {
            return cmacAes(sessionKey, byteArrayOf(counter.toByte()) + context)
        }
        val encKey = derive(key, encContext, 1)
        val macKeyServer = derive(key, macContext, 1) + derive(key, macContext, 2)
        val macKeyClient = derive(key, macContext, 3) + derive(key, macContext, 4)
        return Triple(encKey, macKeyServer, macKeyClient)
    }
}

