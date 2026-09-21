package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.SignedMessage
import org.samfun.ktvine.utils.KtvineException
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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
                "staging" to Cdm.STAGING_PRIVACY_CERT,
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

    @Test
    fun `test both wrapped and bare certificates resolve to the same provider`() {
        runBlocking {
            val cdm = cdm()

            // The bundled constants are SignedMessage-wrapped SignedDrmCertificates.
            val wrapped = Base64.decode(Cdm.COMMON_PRIVACY_CERT)
            val unwrapped = SignedMessage.ADAPTER.decode(wrapped)
            assertEquals(SignedMessage.MessageType.SERVICE_CERTIFICATE, unwrapped.type)
            val bare = unwrapped.msg!!.toByteArray()

            val viaWrapper = cdm.open()
            assertEquals("license.widevine.com", cdm.setServiceCertificate(viaWrapper, wrapped))

            // A bare SignedDrmCertificate also decodes as a SignedMessage; only comparing
            // the re-encoding against the input keeps this on the right branch.
            val viaBare = cdm.open()
            assertEquals("license.widevine.com", cdm.setServiceCertificate(viaBare, bare))

            assertEquals(
                cdm.getServiceCertificate(viaWrapper),
                cdm.getServiceCertificate(viaBare),
                "both forms must store the same SignedDrmCertificate",
            )
        }
    }

    @Test
    fun `test a corrupt certificate is rejected`() {
        runBlocking {
            val cdm = cdm()
            val sessionId = cdm.open()
            assertFailsWith<KtvineException> {
                cdm.setServiceCertificate(sessionId, byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8))
            }
        }
    }
}
