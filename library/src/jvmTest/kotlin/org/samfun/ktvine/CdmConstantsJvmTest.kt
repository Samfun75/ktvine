package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.SignedMessage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

class CdmConstantsJvmTest {

    private fun cdm() = Cdm(DeviceTypes.ANDROID, ClientIdentification(), ByteArray(0))

    @Test
    fun `test service certificate challenge is a SERVICE_CERTIFICATE_REQUEST message`() {
        val decoded = SignedMessage.ADAPTER.decode(Cdm.SERVICE_CERTIFICATE_CHALLENGE)
        assertEquals(SignedMessage.MessageType.SERVICE_CERTIFICATE_REQUEST, decoded.type)
    }

    @Test
    fun `test bundled privacy certs verify against the Google root certificate`() {
        runBlocking {
            val cdm = cdm()
            for ((name, cert) in listOf(
                "common" to Cdm.COMMON_PRIVACY_CERT,
                "staging" to Cdm.STAGING_PRIVACY_CERT
            )) {
                val sessionId = cdm.open()
                // setServiceCertificate verifies the RSA-PSS signature against the root cert,
                // so a truncated or mistyped constant fails here rather than at request time.
                val providerId = cdm.setServiceCertificate(sessionId, cert)
                assertNotNull(providerId, "$name privacy cert produced no provider id")
                assertNotNull(cdm.getServiceCertificate(sessionId), "$name cert was not stored")
                cdm.close(sessionId)
            }
        }
    }

    @Test
    fun `test bundled privacy certs name the expected providers`() {
        runBlocking {
            val cdm = cdm()
            val common = cdm.open()
            assertEquals("license.widevine.com", cdm.setServiceCertificate(common, Cdm.COMMON_PRIVACY_CERT))

            val staging = cdm.open()
            assertEquals("staging.google.com", cdm.setServiceCertificate(staging, Cdm.STAGING_PRIVACY_CERT))
        }
    }
}
