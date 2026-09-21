package org.samfun.ktvine

import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.utils.kidToUuid
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.uuid.Uuid

class KidToUuidTest {

    @Test
    fun `test digit string kid is read as a number`() {
        // Widevine's own integration content sends this KID as 16 ASCII digits.
        // It used to be Base64-decoded, yielding d34d34d3-4d34-d34d-34d3-4d3500000000.
        assertEquals(
            Uuid.parse("00000000-0000-0000-0000-000000000001"),
            "0000000000000001".encodeUtf8().kidToUuid(),
        )
        assertEquals(
            Uuid.parse("00000000-0000-0000-0000-000000000007"),
            "0000000000000007".encodeUtf8().kidToUuid(),
        )
    }

    @Test
    fun `test raw 16 byte kid is read big-endian`() {
        assertEquals(
            Uuid.parse("eb676abb-cb34-5e96-bbcf-616630f1a3da"),
            "eb676abbcb345e96bbcf616630f1a3da".decodeHex().kidToUuid(),
        )
    }

    @Test
    fun `test short non-digit kid is zero padded on the right`() {
        assertEquals(
            Uuid.parse("abcd0000-0000-0000-0000-000000000000"),
            byteArrayOf(0xAB.toByte(), 0xCD.toByte()).toByteString().kidToUuid(),
        )
    }

    @Test
    fun `test single ascii digit kid takes the numeric path`() {
        // Widevine's test content ships a 1-byte KID of 0x35, which is ASCII '5'.
        // pywidevine reads that as the number 5, not as the byte 0x35.
        assertEquals(
            Uuid.parse("00000000-0000-0000-0000-000000000005"),
            byteArrayOf(0x35).toByteString().kidToUuid(),
        )
    }

    @Test
    fun `test missing kid becomes the nil uuid`() {
        assertEquals(Uuid.NIL, null.kidToUuid())
        assertEquals(Uuid.NIL, ByteArray(0).toByteString().kidToUuid())
    }

    @Test
    fun `test base64 kid strings go through the string overload`() {
        assertEquals(
            Uuid.parse("00000000-0000-0000-0000-000000000001"),
            "MDAwMDAwMDAwMDAwMDAwMQ==".kidToUuid(),
        )
    }
}
