package org.samfun.ktvine

import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.SignedDrmCertificate
import java.nio.file.Files
import java.nio.file.Paths
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class DeviceAndroidTest {

    private fun readTestFile(name: String): ByteArray {
        // Try module-relative path first (when working dir is library/)
        val modulePath = Paths.get(
            "src", "commonTest", "kotlin", "org", "samfun", "ktvine", "device", name
        )
        if (Files.exists(modulePath)) return Files.readAllBytes(modulePath)

        // Fallback to repo-root-relative path
        val rootPath = Paths.get(
            "library", "src", "commonTest", "kotlin", "org", "samfun", "ktvine", "device", name
        )
        return Files.readAllBytes(rootPath)
    }

    private fun pemToDer(pemBytes: ByteArray): ByteArray {
        val pem = String(pemBytes)
        val base64 = pem
            .lines()
            .filter { !it.startsWith("---") && it.isNotBlank() }
            .joinToString("")
        return Base64.decode(base64)
    }

    @Test
    fun loads_wvd_v2_from_wvd_file_android() {
        val data = try { readTestFile("google_avd.wvd") } catch (_: Throwable) { return }
        val device = Device.loads(data)

        val clientId = ClientIdentification.ADAPTER.decode(device.clientId.encode())
        val signed = SignedDrmCertificate.ADAPTER.decode(clientId.token!!)
        val drm = DrmCertificate.ADAPTER.decode(signed.drm_certificate!!)

        // Assertions
        assertEquals(DeviceTypes.ANDROID, device.type)
        assertEquals(3, device.securityLevel)

        // Private key check if available
        val expectedPk: ByteArray? = try { pemToDer(readTestFile("private_key.pem")) } catch (_: Throwable) { null }
        if (expectedPk != null) {
            assertEquals(expectedPk.toList(), device.privateKeyDer.toList())
        } else {
            assert(device.privateKeyDer.isNotEmpty())
        }

        // ClientId check if available
        val expectedClientId: ByteArray? = try { readTestFile("client_id.bin") } catch (_: Throwable) { null }
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
