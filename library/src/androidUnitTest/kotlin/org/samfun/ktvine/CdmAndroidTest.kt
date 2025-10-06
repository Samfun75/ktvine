package org.samfun.ktvine

import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.proto.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.util.Base64
import java.util.UUID

class CdmAndroidTest {

    private fun makeDevice(privKeyDer: ByteArray): Device = Device(
        type = DeviceTypes.ANDROID,
        securityLevel = 3,
        flags = emptyMap(),
        privateKeyDer = privKeyDer,
        clientId = ClientIdentification(),
        vmp = null,
        systemId = 1
    )

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

    private fun rsaKpg(): KeyPairGenerator {
        return try {
            KeyPairGenerator.getInstance("RSA")
        } catch (_: Throwable) {
            KeyPairGenerator.getInstance("RSA", "SunRsaSign")
        }
    }

    @Test
    fun privacy_mode_true_uses_encrypted_client_id_android() {
        val kpg = rsaKpg().apply { initialize(2048, SecureRandom()) }
        val kp = kpg.generateKeyPair()
        val device = makeDevice(kp.private.encoded)
        val cdm = Cdm.fromDevice(device)
        val sessionId = cdm.open()

        val certBytes = Base64.getDecoder().decode(Cdm.common_privacy_cert_b64)
        val providerId = providerIdFromSignedOrWrappedCert(certBytes)
        val returned = cdm.setServiceCertificate(sessionId, certBytes)
        assertEquals(providerId, returned)

        val kid = UUID.randomUUID()
        val psshHeader = WidevinePsshData(key_ids = listOf(kid.toByteArray().toByteString()))
        val pssh = PSSH(psshHeader.encode())

        val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING, privacyMode = true)
        val smReq = SignedMessage.ADAPTER.decode(challenge)
        val lr = LicenseRequest.ADAPTER.decode(smReq.msg!!)

        assertNull(lr.client_id)
        assertNotNull(lr.encrypted_client_id)
        assertEquals(providerId, lr.encrypted_client_id.provider_id)
    }

    @Test
    fun privacy_mode_false_sends_plain_client_id_android() {
        val kpg = rsaKpg().apply { initialize(2048, SecureRandom()) }
        val kp = kpg.generateKeyPair()
        val device = makeDevice(kp.private.encoded)
        val cdm = Cdm.fromDevice(device)
        val sessionId = cdm.open()

        val certBytes = Base64.getDecoder().decode(Cdm.common_privacy_cert_b64)
        cdm.setServiceCertificate(sessionId, certBytes)

        val kid = UUID.randomUUID()
        val psshHeader = WidevinePsshData(key_ids = listOf(kid.toByteArray().toByteString()))
        val pssh = PSSH(psshHeader.encode())

        val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING, privacyMode = false)
        val smReq = SignedMessage.ADAPTER.decode(challenge)
        val lr = LicenseRequest.ADAPTER.decode(smReq.msg!!)

        assertNotNull(lr.client_id)
        assertNull(lr.encrypted_client_id)
    }
}
