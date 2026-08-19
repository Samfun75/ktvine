package org.samfun.ktvine

import org.samfun.ktvine.crypto.pkcs7Pad
import org.samfun.ktvine.crypto.pkcs7Unpad
import org.samfun.ktvine.crypto.randomBytes
import org.samfun.ktvine.crypto.randomInt
import org.samfun.ktvine.utils.ValueException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class CryptoTest {

    @Test
    fun `test random bytes are the requested length and not repeated`() {
        assertEquals(0, randomBytes(0).size)
        assertEquals(16, randomBytes(16).size)

        val draws = List(64) { randomBytes(16).toList() }
        assertEquals(draws.size, draws.toSet().size, "randomBytes repeated a 16-byte draw")
    }

    @Test
    fun `test key control nonce range never yields a non-positive value`() {
        // The proto field is uint32 but Wire maps it to a signed Int, so a negative draw
        // would serialise as a 10-byte varint. kotlin.random.Random.nextInt() used to make
        // one roughly half the time.
        repeat(10_000) {
            val nonce = randomInt(1, Int.MAX_VALUE)
            assertTrue(nonce > 0, "randomInt produced a non-positive nonce: $nonce")
        }
    }

    @Test
    fun `test random int covers its range`() {
        val draws = List(1_000) { randomInt(0, 4) }
        assertTrue(draws.all { it in 0..3 }, "randomInt escaped its bounds")
        assertEquals(setOf(0, 1, 2, 3), draws.toSet(), "randomInt did not cover its range")
    }

    @Test
    fun `test pkcs7 pad unpad round trip at every length`() {
        for (len in 0..48) {
            val data = ByteArray(len) { (it and 0xFF).toByte() }
            val padded = pkcs7Pad(data)
            assertEquals(0, padded.size % 16, "padded length is not a multiple of the block size")
            assertTrue(padded.size > data.size, "padding must always add at least one byte")
            assertContentEquals(data, pkcs7Unpad(padded), "round trip failed for length $len")
        }
    }

    @Test
    fun `test pkcs7 unpad rejects unpadded data instead of throwing AIOOBE`() {
        // Trailing byte 0x41 (65) exceeds the array length; this used to index negatively.
        assertFailsWith<ValueException> { pkcs7Unpad(ByteArray(16) { 0x41 }) }
    }

    @Test
    fun `test pkcs7 unpad rejects malformed padding`() {
        // Padding length of zero is never valid.
        assertFailsWith<ValueException> { pkcs7Unpad(ByteArray(16)) }

        // Padding length larger than the block size.
        assertFailsWith<ValueException> { pkcs7Unpad(ByteArray(32) { 17 }) }

        // Correct length byte, but an inconsistent padding byte before it.
        val inconsistent = ByteArray(16) { 4 }.also { it[13] = 9 }
        assertFailsWith<ValueException> { pkcs7Unpad(inconsistent) }

        assertFailsWith<ValueException> { pkcs7Unpad(ByteArray(0)) }
        assertFailsWith<ValueException> { pkcs7Unpad(ByteArray(17) { 1 }) }
    }

    @Test
    fun `test pkcs7 unpad accepts a full block of padding`() {
        val fullBlock = ByteArray(16) { 16 }
        assertEquals(0, pkcs7Unpad(fullBlock).size)
    }
}
