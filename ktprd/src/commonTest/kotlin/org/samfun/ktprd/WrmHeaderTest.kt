package org.samfun.ktprd

import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktprd.utils.InvalidChecksumException
import org.samfun.ktprd.utils.InvalidWrmHeaderException
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.encodeToUtf16LE
import org.samfun.ktvine.utils.toLittleEndianByteArray
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Pins the `WRMHEADER` checksum algorithms and the protocol version a challenge declares.
 *
 * The checksum is what tells a caller the key a license handed back is the key the content was
 * encrypted with, so the expected values here were computed independently of ktprd — with the
 * JDK's own AES-ECB and SHA-1 — rather than by recording what this code produces.
 */
class WrmHeaderTest {

    private val kid = Uuid.parse("8b037e71-1d3f-4a3c-9b1e-2c5d6f708192")
    private val contentKey = byteArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)

    /** `AES-ECB(contentKey, kid_le)[0..8]`. */
    private val aesctrChecksum = "5GKO/BV/DY4="

    /** `SHA-1` five times over the key right-padded to 21 bytes, first seven bytes. */
    private val cocktailChecksum = "8IDSk8PNdg=="

    private fun header(algId: String, checksum: String?, version: String = "4.3.0.0"): String {
        val attributes = buildString {
            append(" ALGID=\"").append(algId).append('"')
            if (checksum != null) append(" CHECKSUM=\"").append(checksum).append('"')
            append(" VALUE=\"").append(Base64.encode(kid.toLittleEndianByteArray())).append('"')
        }
        return "<WRMHEADER xmlns=\"${PlayreadyHeader.NAMESPACE}\" version=\"$version\">" +
            "<DATA><PROTECTINFO><KIDS><KID$attributes></KID></KIDS></PROTECTINFO></DATA></WRMHEADER>"
    }

    @Test
    fun `test the AESCTR checksum matches the value AES-ECB produces`() = runTest {
        val wrm = WrmHeader.parse(header("AESCTR", aesctrChecksum))
        assertTrue(wrm.verifyChecksum(kid, contentKey))
    }

    @Test
    fun `test the COCKTAIL checksum matches five rounds of SHA-1`() = runTest {
        val wrm = WrmHeader.parse(header("COCKTAIL", cocktailChecksum))
        assertTrue(wrm.verifyChecksum(kid, contentKey))
    }

    @Test
    fun `test each algorithm rejects a checksum made by the other`() = runTest {
        assertFalse(WrmHeader.parse(header("AESCTR", cocktailChecksum)).verifyChecksum(kid, contentKey))
        assertFalse(WrmHeader.parse(header("COCKTAIL", aesctrChecksum)).verifyChecksum(kid, contentKey))
    }

    @Test
    fun `test a key that differs by one bit is refused`() = runTest {
        val wrong = contentKey.copyOf().also { it[15] = (it[15].toInt() xor 1).toByte() }

        assertFalse(WrmHeader.parse(header("AESCTR", aesctrChecksum)).verifyChecksum(kid, wrong))
        assertFalse(WrmHeader.parse(header("COCKTAIL", cocktailChecksum)).verifyChecksum(kid, wrong))
    }

    @Test
    fun `test a key id the header does not declare is an error rather than a false`() = runTest {
        val wrm = WrmHeader.parse(header("AESCTR", aesctrChecksum))
        val other = Uuid.parse("00000000-0000-0000-0000-000000000001")

        assertFailsWith<InvalidChecksumException> { wrm.verifyChecksum(other, contentKey) }
    }

    @Test
    fun `test a header carrying no checksum cannot be checked`() = runTest {
        val wrm = WrmHeader.parse(header("AESCTR", checksum = null))

        assertFailsWith<InvalidChecksumException> { wrm.verifyChecksum(kid, contentKey) }
    }

    @Test
    fun `test an algorithm with no defined checksum is refused`() = runTest {
        val wrm = WrmHeader.parse(header("AESCBC", aesctrChecksum))

        assertFailsWith<InvalidChecksumException> { wrm.verifyChecksum(kid, contentKey) }
    }

    @Test
    fun `test the protocol version follows the header version`() {
        assertEquals(5, WrmHeader.parse(header("AESCTR", aesctrChecksum, version = "4.3.0.0")).protocolVersion)
        assertEquals(4, WrmHeader.parse(header("AESCTR", aesctrChecksum, version = "4.2.0.0")).protocolVersion)

        val v41 = "<WRMHEADER xmlns=\"${PlayreadyHeader.NAMESPACE}\" version=\"4.1.0.0\"><DATA><PROTECTINFO>" +
            "<KID VALUE=\"${Base64.encode(kid.toLittleEndianByteArray())}\"></KID>" +
            "</PROTECTINFO></DATA></WRMHEADER>"
        assertEquals(1, WrmHeader.parse(v41).protocolVersion)
    }

    @Test
    fun `test the document is kept verbatim so a signature can cover it`() {
        val xml = header("AESCTR", aesctrChecksum)

        assertEquals(xml, WrmHeader.parse(xml).xml)
    }

    @Test
    fun `test a bare header is accepted both directly and through a PSSH`() {
        val xml = header("AESCTR", aesctrChecksum)

        assertEquals(xml, WrmHeader.from(xml).xml)
        assertEquals(xml, WrmHeader.from(PSSH(xml.encodeToUtf16LE())).single().xml)
    }

    @Test
    fun `test something that is not a header is refused`() {
        assertFailsWith<InvalidWrmHeaderException> { WrmHeader.parse("<NOTAHEADER></NOTAHEADER>") }
    }
}
