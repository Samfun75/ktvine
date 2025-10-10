package org.samfun.ktvine

import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.SignedDrmCertificate
import java.nio.file.Files
import java.nio.file.Paths
import java.util.*
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertFailsWith

class DeviceJvmTest {

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
        return Base64.getDecoder().decode(base64)
    }

    @Test
    fun loads_wvd_v2_from_client_id_and_private_key() {
        // Read inputs from provided device test folder
        val clientIdRaw = readTestFile("client_id.bin")
        val privateKeyDer = pemToDer(readTestFile("private_key.pem"))

        // Build a v2 WVD with ANDROID type and security level 3
        val wvd = Device.buildWvdV2(DeviceTypes.ANDROID, 3, privateKeyDer, clientIdRaw)

        // Load using Device.loads(bytes)
        val device = Device.loads(wvd)

        // Parse expected values directly from client_id for comparison
        val clientId = ClientIdentification.ADAPTER.decode(clientIdRaw)
        val signed = SignedDrmCertificate.ADAPTER.decode(clientId.token!!)
        val drm = DrmCertificate.ADAPTER.decode(signed.drm_certificate!!)

        // Assertions
        assertEquals(DeviceTypes.ANDROID, device.type)
        assertEquals(3, device.securityLevel)
        assertEquals(privateKeyDer.toList(), device.privateKeyDer.toList())
        assertEquals(clientIdRaw.toList(), device.clientId.encode().toList())
        assertEquals(drm.system_id!!, device.systemId)

        // VMP checks: device.vmp is present iff client_id.vmp_data present
        if (clientId.vmp_data != null) {
            assertNotNull(device.vmp, "Expected VMP to be parsed when vmp_data is present")
        } else {
            assertNull(device.vmp, "Expected VMP to be null when vmp_data is absent")
        }

        // Also test base64 variant of loads(String)
        val b64 = Base64.getEncoder().encodeToString(wvd)
        val deviceB64 = Device.loads(b64)
        assertEquals(device.systemId, deviceB64.systemId)
        println("SysId: ${device.systemId}, ${deviceB64.systemId}")
        assertEquals(device.type, deviceB64.type)
        println("Type: ${device.type}, ${deviceB64.type}")
        assertEquals(device.securityLevel, deviceB64.securityLevel)
        println("SecLvl: ${device.securityLevel}, ${deviceB64.securityLevel}")
        assertEquals(device.clientId.encode().toList(), deviceB64.clientId.encode().toList())
        println("ClientId: ${device.clientId.encode().toList()}, ${deviceB64.clientId.encode().toList()}")
    }

    @Test
    fun loads_wvd_v2_from_wvd_file() {
        // Read inputs from provided device test folder
        val data = try { readTestFile("google_avd.wvd") } catch (_: Throwable) { return }
        val device = Device.loads(data)

        // Parse expected values directly from client_id for comparison
        val clientId = ClientIdentification.ADAPTER.decode(device.clientId.encode())
        val signed = SignedDrmCertificate.ADAPTER.decode(clientId.token!!)
        val drm = DrmCertificate.ADAPTER.decode(signed.drm_certificate!!)

        // Assertions
        assertEquals(DeviceTypes.ANDROID, device.type)
        assertEquals(3, device.securityLevel)
        // If private_key.pem is available, compare exactly; otherwise, just ensure key is present
        val expectedPk: ByteArray? = try { pemToDer(readTestFile("private_key.pem")) } catch (_: Throwable) { null }
        if (expectedPk != null) {
            assertEquals(expectedPk.toList(), device.privateKeyDer.toList())
        } else {
            assert(device.privateKeyDer.isNotEmpty())
        }
        // If client_id.bin is available, compare exactly; otherwise, just ensure a non-empty client id
        val expectedClientId: ByteArray? = try { readTestFile("client_id.bin") } catch (_: Throwable) { null }
        if (expectedClientId != null) {
            assertEquals(expectedClientId.toList(), device.clientId.encode().toList())
        } else {
            assert(device.clientId.encode().isNotEmpty())
        }
        assertEquals(drm.system_id!!, device.systemId)

        // VMP checks: device.vmp is present iff client_id.vmp_data present
        if (clientId.vmp_data != null) {
            assertNotNull(device.vmp, "Expected VMP to be parsed when vmp_data is present")
        } else {
            assertNull(device.vmp, "Expected VMP to be null when vmp_data is absent")
        }

        // Also test base64 variant of loads(String)
        val b64 = Base64.getEncoder().encodeToString(data)
        val deviceB64 = Device.loads(b64)
        assertEquals(device.systemId, deviceB64.systemId)
        println("SysId: ${device.systemId}, ${deviceB64.systemId}")
        assertEquals(device.type, deviceB64.type)
        println("Type: ${device.type}, ${deviceB64.type}")
        assertEquals(device.securityLevel, deviceB64.securityLevel)
        println("SecLvl: ${device.securityLevel}, ${deviceB64.securityLevel}")
        assertEquals(device.clientId.encode().toList(), deviceB64.clientId.encode().toList())
        println("ClientId: ${device.clientId.encode().toList()}, ${deviceB64.clientId.encode().toList()}")
    }

    @Test
    fun loads_google_avd_wvd_if_present() {
        // Optional test: skip if file missing
        val data = try { readTestFile("google_avd.wvd") } catch (_: Throwable) { return }
        val device = Device.loads(data)
        // Basic sanity checks
        println("SysId: ${device.systemId}")
        println("Type: ${device.type}")
        println("SecLvl: ${device.securityLevel}")
        println("ClientId: ${device.clientId.encode().toList()}")
        assertNotNull(device.clientId)
        assert(device.systemId > 0)
    }

    // Negative tests
    @Test
    fun loads_base64_invalid_throws() {
        assertFailsWith<ValueException> {
            Device.loads("not-base64!!!")
        }
    }

    @Test
    fun loads_wrong_magic_throws() {
        // 11 bytes minimum length, but wrong magic
        val bad = byteArrayOf('X'.code.toByte(), 'Y'.code.toByte(), 'Z'.code.toByte()) + ByteArray(8) { 0 }
        assertFailsWith<ValueException> {
            Device.loads(bad)
        }
    }

    @Test
    fun loads_unsupported_version_throws() {
        // 'WVD' + version 1 + filler
        val bytes = byteArrayOf('W'.code.toByte(), 'V'.code.toByte(), 'D'.code.toByte(), 1) + ByteArray(7) { 0 }
        assertFailsWith<ValueException> {
            Device.loads(bytes)
        }
    }

    @Test
    fun loads_unknown_device_type_throws() {
        // 'WVD' + version 2 + type 99 + securityLevel + flags + two u16 lengths (zeros)
        val bytes = byteArrayOf(
            'W'.code.toByte(), 'V'.code.toByte(), 'D'.code.toByte(),
            2, // version
            99, // unknown type
            3, // security level
            0, // flags
            0, 0, // priv len
            0, 0  // client len
        )
        assertFailsWith<ValueException> {
            Device.loads(bytes)
        }
    }

    @Test
    fun loads_data_too_short_throws() {
        val tooShort = byteArrayOf(0, 1, 2, 3, 4, 5)
        assertFailsWith<IllegalArgumentException> {
            Device.loads(tooShort)
        }
    }
}
