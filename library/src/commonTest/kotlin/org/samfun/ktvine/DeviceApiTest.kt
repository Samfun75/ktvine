package org.samfun.ktvine

import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.FileHashes
import org.samfun.ktvine.proto.SignedDrmCertificate
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.utils.ValueException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DeviceApiTest {

    private val privateKey = ByteArray(64) { (it and 0xFF).toByte() }

    /** `loads` never checks signatures, so a structurally valid chain is enough. */
    private fun clientId(vmpData: ByteArray? = null): ClientIdentification {
        val drm = DrmCertificate(system_id = 4464).encode()
        val signed = SignedDrmCertificate(drm_certificate = drm.toByteString()).encode()
        return ClientIdentification(
            token = signed.toByteString(),
            vmp_data = vmpData?.toByteString(),
        )
    }

    private fun vmp() = FileHashes(signer = byteArrayOf(1, 2, 3).toByteString()).encode()

    private fun buildV1(clientIdBytes: ByteArray, vmpBytes: ByteArray?, version: Int = 1): ByteArray {
        fun u16(v: Int) = byteArrayOf(((v ushr 8) and 0xFF).toByte(), (v and 0xFF).toByte())
        var out = byteArrayOf('W'.code.toByte(), 'V'.code.toByte(), 'D'.code.toByte()) +
            byteArrayOf(version.toByte()) +
            byteArrayOf(DeviceTypes.ANDROID.value.toByte()) +
            byteArrayOf(3) +
            byteArrayOf(0) +
            u16(privateKey.size) + privateKey +
            u16(clientIdBytes.size) + clientIdBytes
        if (vmpBytes != null) out += u16(vmpBytes.size) + vmpBytes
        return out
    }

    @Test
    fun `test dumps round trips a loaded device`() {
        val original = Device.buildWvdV2(
            type = DeviceTypes.CHROME,
            securityLevel = 1,
            privateKeyDer = privateKey,
            clientIdBytes = clientId().encode(),
            rawFlags = 0x2A,
        )

        val device = Device.loads(original)
        assertContentEquals(original, device.dumps(), "dumps() must reproduce the input blob")

        // Including the reserved flags byte, which used to be read and discarded.
        assertEquals(0x2A, device.rawFlags)
        val reloaded = Device.loads(device.dumps())
        assertEquals(device.type, reloaded.type)
        assertEquals(device.securityLevel, reloaded.securityLevel)
        assertEquals(device.systemId, reloaded.systemId)
        assertEquals(device.rawFlags, reloaded.rawFlags)
        assertContentEquals(device.privateKeyDer, reloaded.privateKeyDer)
    }

    @Test
    fun `test migrate folds the v1 vmp block into the client id`() {
        val vmpBytes = vmp()
        val v1 = buildV1(clientId().encode(), vmpBytes)

        val device = Device.migrate(v1)

        assertEquals(DeviceTypes.ANDROID, device.type)
        assertEquals(3, device.securityLevel)
        assertNotNull(device.vmp, "the trailing VMP block should land in client_id.vmp_data")
        assertContentEquals(vmpBytes, device.clientId.vmp_data!!.toByteArray())

        // The migrated blob must itself be loadable as v2.
        assertEquals(device.systemId, Device.loads(device.dumps()).systemId)
    }

    @Test
    fun `test migrate works without a vmp block`() {
        val device = Device.migrate(buildV1(clientId().encode(), null))
        assertNull(device.vmp)
    }

    @Test
    fun `test migrate rejects blobs that are not v1`() {
        val v2 = Device.buildWvdV2(DeviceTypes.ANDROID, 3, privateKey, clientId().encode())
        val alreadyMigrated = assertFailsWith<ValueException> { Device.migrate(v2) }
        assertTrue(alreadyMigrated.message!!.contains("already migrated"), alreadyMigrated.message!!)

        val v0 = assertFailsWith<ValueException> { Device.migrate(buildV1(clientId().encode(), null, version = 0)) }
        assertTrue(v0.message!!.contains("v0"), v0.message!!)

        assertFailsWith<ValueException> { Device.migrate(buildV1(clientId().encode(), null, version = 7)) }
    }

    @Test
    fun `test loads points v1 blobs at migrate`() {
        val failure = assertFailsWith<ValueException> {
            Device.loads(buildV1(clientId().encode(), vmp()))
        }
        assertTrue(failure.message!!.contains("migrate"), failure.message!!)
    }

    @Test
    fun `test loads rejects v0 distinctly from a higher version`() {
        val v0 = assertFailsWith<ValueException> { Device.loads(buildV1(clientId().encode(), null, version = 0)) }
        assertTrue(v0.message!!.contains("v0"), v0.message!!)

        val v9 = assertFailsWith<ValueException> { Device.loads(buildV1(clientId().encode(), null, version = 9)) }
        assertTrue(v9.message!!.contains("Unsupported WVD version 9"), v9.message!!)
    }

    @Test
    fun `test undecodable vmp data fails loudly instead of being dropped`() {
        // Field 1 declared as a 200-byte length-delimited value with no bytes behind it.
        val corruptVmp = byteArrayOf(0x0A, 200.toByte(), 0x01)
        val wvd = Device.buildWvdV2(DeviceTypes.ANDROID, 3, privateKey, clientId(corruptVmp).encode())

        assertFailsWith<DecodeException> { Device.loads(wvd) }
    }
}
