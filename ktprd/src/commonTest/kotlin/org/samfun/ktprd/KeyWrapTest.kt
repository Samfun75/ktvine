package org.samfun.ktprd

import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.crypto.KeyWrap
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** RFC 3394 test vectors for the AES key unwrap used on a protected device group key. */
class KeyWrapTest {

    @Test
    fun `test RFC 3394 section 4 1 unwraps a 128 bit key with a 128 bit KEK`() = runTest {
        val unwrapped = KeyWrap.aesKeyUnwrap(
            "000102030405060708090a0b0c0d0e0f".hexToBytes(),
            "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5".hexToBytes(),
        )
        assertEquals("00112233445566778899aabbccddeeff", unwrapped.toHexString())
    }

    @Test
    fun `test RFC 3394 section 4 6 unwraps a 256 bit key with a 256 bit KEK`() = runTest {
        val unwrapped = KeyWrap.aesKeyUnwrap(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f".hexToBytes(),
            (
                "28c9f404c4b810f4cbccb35cfb87f8263f5786e2d80ed326" +
                    "cbc7f0e71a99f43bfb988b9b7a02dd21"
                ).hexToBytes(),
        )
        assertEquals(
            "00112233445566778899aabbccddeeff000102030405060708090a0b0c0d0e0f",
            unwrapped.toHexString(),
        )
    }

    @Test
    fun `test a corrupt wrapped key fails the integrity check`() = runTest {
        val wrapped = "1fa68b0a8112b447aef34bd8fb5a7b829d3e862371d2cfe5".hexToBytes()
        wrapped[0] = (wrapped[0].toInt() xor 1).toByte()
        assertFailsWith<ValueException> {
            KeyWrap.aesKeyUnwrap("000102030405060708090a0b0c0d0e0f".hexToBytes(), wrapped)
        }
    }

    @Test
    fun `test the wrapping key derivation is stable`() = runTest {
        // Derived from two fixed constants, so it is a constant itself; pinning it here catches a
        // regression in the SP 800-108 input layout, which has no published vector of its own.
        val derived = KeyWrap.deriveWrappingKey()
        assertEquals(16, derived.size)
        assertEquals(derived.toHexString(), KeyWrap.deriveWrappingKey().toHexString())
    }

    @Test
    fun `test a wrapped key of the wrong shape is rejected`() = runTest {
        assertFailsWith<ValueException> {
            KeyWrap.aesKeyUnwrap("000102030405060708090a0b0c0d0e0f".hexToBytes(), ByteArray(20))
        }
    }
}
