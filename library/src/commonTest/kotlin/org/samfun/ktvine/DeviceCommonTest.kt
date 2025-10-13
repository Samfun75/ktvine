package org.samfun.ktvine

import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.utils.ValueException
import kotlin.test.Test
import kotlin.test.assertFailsWith

class DeviceCommonTest {

    // These tests avoid any platform-specific file I/O and validate error handling across all targets.

    @Test
    fun `test loads base64 invalid throws common`() {
        assertFailsWith<ValueException> {
            Device.loads("this is not base64$$$")
        }
    }

    @Test
    fun `test loads wrong magic throws common`() {
        val bad = byteArrayOf('X'.code.toByte(), 'Y'.code.toByte(), 'Z'.code.toByte()) + ByteArray(8) { 0 }
        assertFailsWith<ValueException> { Device.loads(bad) }
    }

    @Test
    fun `test loads unsupported version throws common`() {
        val bytes = byteArrayOf('W'.code.toByte(), 'V'.code.toByte(), 'D'.code.toByte(), 1) + ByteArray(7) { 0 }
        assertFailsWith<ValueException> { Device.loads(bytes) }
    }

    @Test
    fun `test loads unknown device type throws common`() {
        val bytes = byteArrayOf(
            'W'.code.toByte(), 'V'.code.toByte(), 'D'.code.toByte(),
            2, // version
            99, // unknown type
            3, // security level
            0, // flags
            0, 0, // priv len
            0, 0  // client len
        )
        assertFailsWith<ValueException> { Device.loads(bytes) }
    }

    @Test
    fun `test loads data too short throws common`() {
        val tooShort = byteArrayOf(0, 1, 2, 3, 4, 5)
        assertFailsWith<IllegalArgumentException> { Device.loads(tooShort) }
    }

    @Test
    fun `test loads base64 roundtrip with random bytes still fails common`() {
        // Random bytes made base64: should fail due to wrong magic
        val random = ByteArray(32) { it.toByte() }
        val b64 = random.toByteString().base64()
        assertFailsWith<ValueException> { Device.loads(b64) }
    }
}
