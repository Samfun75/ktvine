package org.samfun.ktvine

import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.SignedDrmCertificate
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DeviceAndroidTest {

    private fun pemToDer(pemBytes: ByteArray): ByteArray {
        val pem = String(pemBytes)
        val base64 = pem
            .lines()
            .filter { !it.startsWith("---") && it.isNotBlank() }
            .joinToString("")
        return Base64.decode(base64)
    }

    @Test
    fun `test loads wvd v2 from wvd file android`() {
        val data = TestFixtures.orSkip("device/google_avd.wvd") ?: return
        val device = Device.loads(data)

        val clientId = ClientIdentification.ADAPTER.decode(device.clientId.encode())
        val signed = SignedDrmCertificate.ADAPTER.decode(clientId.token!!)
        val drm = DrmCertificate.ADAPTER.decode(signed.drm_certificate!!)

        // Assertions
        assertEquals(DeviceTypes.ANDROID, device.type)
        assertEquals(3, device.securityLevel)

        // Private key check if available
        val expectedPk: ByteArray? = TestFixtures.readOrNull("device/private_key.pem")?.let { pemToDer(it) }
        if (expectedPk != null) {
            assertEquals(expectedPk.toList(), device.privateKeyDer.toList())
        } else {
            assert(device.privateKeyDer.isNotEmpty())
        }

        // ClientId check if available
        val expectedClientId: ByteArray? = TestFixtures.readOrNull("device/client_id.bin")
        if (expectedClientId != null) {
            assertEquals(expectedClientId.toList(), device.clientId.encode().toList())
        } else {
            assert(device.clientId.encode().isNotEmpty())
        }

        assertEquals(drm.system_id!!, device.systemId)

        if (clientId.vmp_data != null) {
            assertNotNull(device.vmp)
        } else {
            assertNull(device.vmp)
        }

        // Base64 variant
        val b64 = Base64.encode(data)
        val deviceB64 = Device.loads(b64)
        assertEquals(device.systemId, deviceB64.systemId)
        assertEquals(device.type, deviceB64.type)
        assertEquals(device.securityLevel, deviceB64.securityLevel)
        assertEquals(device.clientId.encode().toList(), deviceB64.clientId.encode().toList())
    }
}
