package org.samfun.ktvine

import okio.ByteString.Companion.toByteString
import okio.FileSystem
import okio.Path.Companion.toPath
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.SignedDrmCertificate
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DeviceFileIoJvmTest {

    private val tempDir = FileSystem.SYSTEM_TEMPORARY_DIRECTORY / "ktvine-device-io-test"

    @AfterTest
    fun cleanUp() {
        FileSystem.SYSTEM.deleteRecursively(tempDir, mustExist = false)
    }

    private fun device(): Device {
        val drm = DrmCertificate(system_id = 4464).encode()
        val signed = SignedDrmCertificate(drm_certificate = drm.toByteString()).encode()
        val clientId = ClientIdentification(token = signed.toByteString())
        return Device.loads(
            Device.buildWvdV2(DeviceTypes.ANDROID, 3, ByteArray(32) { it.toByte() }, clientId.encode())
        )
    }

    @Test
    fun `test dump and load round trip through the file system`() {
        val original = device()
        // Nested path on purpose: dump() must create the parent directories.
        val path = tempDir / "nested" / "device.wvd"

        original.dump(path)
        assertTrue(FileSystem.SYSTEM.exists(path), "dump() did not write the file")

        val loaded = Device.load(path)
        assertEquals(original.systemId, loaded.systemId)
        assertEquals(original.type, loaded.type)
        assertEquals(original.securityLevel, loaded.securityLevel)
        assertContentEquals(original.privateKeyDer, loaded.privateKeyDer)
        assertContentEquals(original.dumps(), loaded.dumps())
    }

    @Test
    fun `test dump and load accept string paths`() {
        val original = device()
        val path = (tempDir / "by-string.wvd").toString()

        original.dump(path)

        assertContentEquals(original.dumps(), Device.load(path).dumps())
        assertContentEquals(original.dumps(), Device.load(path.toPath()).dumps())
    }
}
