package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.SignedMessage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Covers the RSA-OAEP path, which is only reached when privacy mode is actually on. */
class PrivacyModeJvmTest {

    private fun pssh(): PSSH {
        val xml = TestFixtures.readText("playlist/tears.mpd")
        return PSSH(Regex("""<cenc:pssh\b[^>]*>([^<]+)</cenc:pssh>""").find(xml)!!.groupValues[1].trim())
    }

    private fun decodeRequest(challenge: ByteArray): LicenseRequest =
        LicenseRequest.ADAPTER.decode(SignedMessage.ADAPTER.decode(challenge).msg!!)

    @Test
    fun `test privacy mode encrypts the client id to the service certificate`() {
        runBlocking {
            val data = TestFixtures.orSkip("device/widevine/google_avd.wvd") ?: return@runBlocking
            val cdm = Cdm.fromDevice(Device.loads(data))
            val sessionId = cdm.open()

            cdm.setServiceCertificate(sessionId, Cdm.COMMON_PRIVACY_CERT)
            val request = decodeRequest(cdm.getLicenseChallenge(sessionId, pssh(), privacyMode = true))

            assertNull(request.client_id, "the plaintext client id must not be sent in privacy mode")
            val encrypted = assertNotNull(request.encrypted_client_id)
            assertEquals("license.widevine.com", encrypted.provider_id)
            assertTrue(encrypted.encrypted_client_id!!.size > 0)
            assertEquals(16, encrypted.encrypted_client_id_iv!!.size)
            // RSA-OAEP output is the modulus size; the service cert is 2048-bit.
            assertEquals(256, encrypted.encrypted_privacy_key!!.size)
        }
    }

    @Test
    fun `test privacy mode off sends the plaintext client id`() {
        runBlocking {
            val data = TestFixtures.orSkip("device/widevine/google_avd.wvd") ?: return@runBlocking
            val cdm = Cdm.fromDevice(Device.loads(data))
            val sessionId = cdm.open()

            cdm.setServiceCertificate(sessionId, Cdm.COMMON_PRIVACY_CERT)
            val request = decodeRequest(cdm.getLicenseChallenge(sessionId, pssh(), privacyMode = false))

            assertNotNull(request.client_id)
            assertNull(request.encrypted_client_id)
        }
    }
}
