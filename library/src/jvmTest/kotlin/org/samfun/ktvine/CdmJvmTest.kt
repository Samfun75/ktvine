package org.samfun.ktvine

import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.crypto.*
import org.samfun.ktvine.proto.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

class CdmJvmTest {

    private fun makeDevice(privKeyDer: ByteArray): Device {
        val clientId = ClientIdentification() // minimal
        return Device(
            type = DeviceTypes.CHROME,
            securityLevel = 3,
            flags = emptyMap(),
            privateKeyDer = privKeyDer,
            clientId = clientId,
            vmp = null,
            systemId = 1
        )
    }

    private fun deriveContexts(message: ByteArray): Pair<ByteArray, ByteArray> {
        val encLabel = "ENCRYPTION".encodeToByteArray()
        val macLabel = "AUTHENTICATION".encodeToByteArray()
        val enc = encLabel + byteArrayOf(0) + message + intToBytes(16 * 8)
        val mac = macLabel + byteArrayOf(0) + message + intToBytes(32 * 8 * 2)
        return enc to mac
    }

    private fun intToBytes(v: Int): ByteArray = byteArrayOf(
        ((v ushr 24) and 0xFF).toByte(),
        ((v ushr 16) and 0xFF).toByte(),
        ((v ushr 8) and 0xFF).toByte(),
        (v and 0xFF).toByte()
    )

    private fun deriveKeys(encCtx: ByteArray, macCtx: ByteArray, key: ByteArray): Triple<ByteArray, ByteArray, ByteArray> {
        fun derive(k: ByteArray, ctx: ByteArray, ctr: Int) = cmacAes(k, byteArrayOf(ctr.toByte()) + ctx)
        val encKey = derive(key, encCtx, 1)
        val macServer = derive(key, macCtx, 1) + derive(key, macCtx, 2)
        val macClient = derive(key, macCtx, 3) + derive(key, macCtx, 4)
        return Triple(encKey, macServer, macClient)
    }

    @Test
    fun endToEnd_license_flow() {
        // 1) Create device keypair
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048, SecureRandom()) }
        val kp = kpg.generateKeyPair()
        val privDer = kp.private.encoded // PKCS#8
        val pubDer = kp.public.encoded   // X.509

        val device = makeDevice(privDer)
        val cdm = Cdm.fromDevice(device)
        val sessionId = cdm.open()

        // 2) Build PSSH with a random KID
        val kid = UUID.randomUUID()
        val psshHeader = WidevinePsshData(key_ids = listOf(kid.toByteArray().toByteString()))
        val pssh = PSSH(psshHeader.encode())

        // 3) Build license challenge
        val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING, privacyMode = false)
        val smReq = SignedMessage.ADAPTER.decode(challenge)
        assertEquals(SignedMessage.MessageType.LICENSE_REQUEST, smReq.type)
        val lr = LicenseRequest.ADAPTER.decode(smReq.msg!!)
        val reqId = lr.content_id!!.widevine_pssh_data!!.request_id!!

        // 4) Build a minimal license matching the request
        val licenseId = LicenseIdentification(request_id = reqId)

        val contentKey = randomBytes(16) // plaintext content key
        val iv = randomBytes(16)

        // derive keys using same algorithm
        val (encCtx, macCtx) = deriveContexts(lr.encode())
        val sessionKey = randomBytes(16)
        val (encKey, macServer, _) = deriveKeys(encCtx, macCtx, sessionKey)

        val wrappedKey = aesCbcEncryptNoPadding(encKey, iv, pkcs7Pad(contentKey))

        val keyContainer = License.KeyContainer(
            id = kid.toByteArray().toByteString(),
            iv = iv.toByteString(),
            key = wrappedKey.toByteString(),
            type = License.KeyContainer.KeyType.CONTENT
        )

        val lic = License(
            id = licenseId,
            key = listOf(keyContainer),
            license_start_time = System.currentTimeMillis() / 1000
        )
        val licBytes = lic.encode()

        val sessionKeyWrapped = rsaOaepEncryptSha1(pubDer, sessionKey)
        val signature = hmacSha256(macServer, licBytes)

        val smRes = SignedMessage(
            type = SignedMessage.MessageType.LICENSE,
            msg = licBytes.toByteString(),
            signature = signature.toByteString(),
            session_key = sessionKeyWrapped.toByteString()
        ).encode()

        // 5) Parse license and assert key
        cdm.parseLicense(sessionId, smRes)
        val keys = cdm.getKeys(sessionId)
        assertEquals(1, keys.size)
        assertEquals(kid, keys[0].kid)
        assertEquals(contentKey.toList(), keys[0].key.toList())
    }

    @Test
    fun service_certificate_errors_and_removal() {
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048, SecureRandom()) }
        val kp = kpg.generateKeyPair()
        val privDer = kp.private.encoded
        val device = makeDevice(privDer)
        val cdm = Cdm.fromDevice(device)
        val sessionId = cdm.open()

        // Removing when none set returns null
        val removed = cdm.setServiceCertificate(sessionId, null)
        assertEquals(null, removed)

        // Passing a random byte array should fail to parse -> DecodeException
        assertFailsWith<DecodeException> {
            cdm.setServiceCertificate(sessionId, randomBytes(64))
        }
    }

    private fun providerIdFromSignedOrWrappedCert(certBytes: ByteArray): String? {
        val sm = try { SignedMessage.ADAPTER.decode(certBytes) } catch (_: Throwable) { null }
        val signed: SignedDrmCertificate = if (sm != null && sm.msg != null) {
            SignedDrmCertificate.ADAPTER.decode(sm.msg)
        } else {
            SignedDrmCertificate.ADAPTER.decode(certBytes)
        }
        val drm = DrmCertificate.ADAPTER.decode(signed.drm_certificate!!)
        return drm.provider_id
    }

    @Test
    fun license_challenge_privacy_mode_true_uses_encrypted_client_id() {
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048, SecureRandom()) }
        val kp = kpg.generateKeyPair()
        val device = makeDevice(kp.private.encoded)
        val cdm = Cdm.fromDevice(device)
        val sessionId = cdm.open()

        // Set a valid service certificate (root-signed)
        val certBytes = Base64.getDecoder().decode(Cdm.common_privacy_cert_b64)
        val providerId = providerIdFromSignedOrWrappedCert(certBytes)
        val returnedProvider = cdm.setServiceCertificate(sessionId, certBytes)
        assertEquals(providerId, returnedProvider)

        val kid = UUID.randomUUID()
        val psshHeader = WidevinePsshData(key_ids = listOf(kid.toByteArray().toByteString()))
        val pssh = PSSH(psshHeader.encode())

        val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING, privacyMode = true)
        val smReq = SignedMessage.ADAPTER.decode(challenge)
        assertEquals(SignedMessage.MessageType.LICENSE_REQUEST, smReq.type)
        val lr = LicenseRequest.ADAPTER.decode(smReq.msg!!)

        assertNull(lr.client_id, "client_id must be omitted in privacy mode when service cert is set")
        assertNotNull(lr.encrypted_client_id, "encrypted_client_id must be present in privacy mode")
        assertEquals(providerId, lr.encrypted_client_id.provider_id)
    }

    @Test
    fun license_challenge_privacy_mode_false_sends_plain_client_id() {
        val kpg = KeyPairGenerator.getInstance("RSA").apply { initialize(2048, SecureRandom()) }
        val kp = kpg.generateKeyPair()
        val device = makeDevice(kp.private.encoded)
        val cdm = Cdm.fromDevice(device)
        val sessionId = cdm.open()

        // Even with a certificate set, privacyMode=false should send plain client_id
        val certBytes = Base64.getDecoder().decode(Cdm.common_privacy_cert_b64)
        cdm.setServiceCertificate(sessionId, certBytes)

        val kid = UUID.randomUUID()
        val psshHeader = WidevinePsshData(key_ids = listOf(kid.toByteArray().toByteString()))
        val pssh = PSSH(psshHeader.encode())

        val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING, privacyMode = false)
        val smReq = SignedMessage.ADAPTER.decode(challenge)
        val lr = LicenseRequest.ADAPTER.decode(smReq.msg!!)

        assertNotNull(lr.client_id, "client_id must be present when privacyMode=false")
        assertNull(lr.encrypted_client_id, "encrypted_client_id must be absent when privacyMode=false")
    }
}
