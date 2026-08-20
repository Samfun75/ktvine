package org.samfun.ktvine

import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.utils.decodeToStringUtf16LE
import org.samfun.ktvine.utils.encodeToUtf16LE
import org.samfun.ktvine.utils.kidToUuid
import org.samfun.ktvine.utils.swapGuidEndianness
import org.samfun.ktvine.utils.toHexString
import org.samfun.ktvine.utils.toUUID
import org.samfun.ktvine.utils.uuidFromByteArray
import org.samfun.ktvine.utils.uuidFromHexByteString
import org.samfun.ktvine.utils.uuidFromLittleEndian
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.uuid.Uuid

/**
 * Covers the helpers that replaced `java.util.UUID`, `java.math.BigInteger` and the
 * charset `expect`/`actual` split, since those were hand-rolled for multiplatform.
 */
class ExtensionsTest {

    @Test
    fun `test uuid to bytes and back round trips`() {
        val uuid = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")
        assertEquals("edef8ba979d64acea3c827dcd51d21ed", uuid.toByteArray().toHexString())
        assertEquals(uuid, uuid.toByteArray().toUUID())
    }

    @Test
    fun `test numeric kid decoding spans both halves of the uuid`() {
        // Replaced BigInteger, so the 64-bit boundary is the interesting case.
        assertEquals(
            Uuid.fromLongs(0L, 0x35L),
            byteArrayOf(0x35).toByteString().uuidFromByteArray()
        )

        // 2^64 exactly: the carry has to reach the high half.
        val twoToThe64 = byteArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0)
        assertEquals(
            Uuid.parse("00000000-0000-0001-0000-000000000000"),
            twoToThe64.toByteString().uuidFromByteArray()
        )

        // A full 16 bytes must survive untouched.
        val full = "0123456789abcdeffedcba9876543210".decodeHex()
        assertEquals(Uuid.parse("01234567-89ab-cdef-fedc-ba9876543210"), full.uuidFromByteArray())
    }

    @Test
    fun `test decimal string kid decoding spans both halves of the uuid`() {
        assertEquals(Uuid.fromLongs(0L, 1L), "0000000000000001".encodeUtf8().kidToUuid())

        // 2^64 = 18446744073709551616, the first value needing the high half.
        assertEquals(
            Uuid.parse("00000000-0000-0001-0000-000000000000"),
            "18446744073709551616".encodeUtf8().kidToUuid()
        )

        // 2^64 - 1 must stay entirely in the low half.
        assertEquals(
            Uuid.parse("00000000-0000-0000-ffff-ffffffffffff"),
            "18446744073709551615".encodeUtf8().kidToUuid()
        )
    }

    @Test
    fun `test hex string kid decoding`() {
        assertEquals(
            Uuid.parse("eb676abb-cb34-5e96-bbcf-616630f1a3da"),
            "eb676abbcb345e96bbcf616630f1a3da".encodeUtf8().uuidFromHexByteString()
        )
    }

    @Test
    fun `test guid endianness swap is its own inverse`() {
        val bigEndian = "d9008212385b3280b3b2f60df62a033e".decodeHex().toByteArray()
        val littleEndian = "128200d95b388032b3b2f60df62a033e".decodeHex().toByteArray()

        assertContentEquals(littleEndian, bigEndian.swapGuidEndianness())
        assertContentEquals(bigEndian, littleEndian.swapGuidEndianness())
        assertEquals(Uuid.parse("d9008212-385b-3280-b3b2-f60df62a033e"), littleEndian.uuidFromLittleEndian())
    }

    @Test
    fun `test utf16le round trips including non-BMP characters`() {
        for (text in listOf("", "PlayReady", "<KID>x</KID>", "naïve — ümlaut", "emoji: 🔐")) {
            assertEquals(text, text.encodeToUtf16LE().decodeToStringUtf16LE(), "round trip failed for '$text'")
        }

        // Little-endian byte order, two bytes per code unit.
        assertContentEquals(byteArrayOf(0x41, 0x00, 0x42, 0x00), "AB".encodeToUtf16LE())
    }
}
