@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine

import okio.Buffer
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.encodeToUtf16LE
import org.samfun.ktvine.utils.toUUID
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * How a PlayReady header reaches [PSSH], in each of the three shapes a caller may hand over.
 *
 * A bare `WRMHEADER` used to be stored verbatim and then fail `keyIds()` with "corrupt" — a hole
 * inherited from pywidevine. It is wrapped into a real PlayReady Object on ingest now.
 */
class PsshPlayreadyIngestTest {

    private val kid = Uuid.parse("11223344-5566-7788-99aa-bbccddeeff00")
    private val secondKid = Uuid.parse("00ffeedd-ccbb-aa99-8877-665544332211")

    private fun header(keyIds: List<Uuid> = listOf(kid)): String =
        PlayreadyHeader.build(keyIds = keyIds, algid = "AESCTR", laUrl = "https://ls.example.com/rights")

    private fun proOf(vararg records: Pair<Int, ByteArray>): ByteArray {
        val body = Buffer().apply {
            writeShortLe(records.size)
            records.forEach { (type, value) ->
                writeShortLe(type)
                writeShortLe(value.size)
                write(value)
            }
        }.readByteArray()
        return Buffer().apply {
            writeIntLe(body.size + 4)
            write(body)
        }.readByteArray()
    }

    @Test
    fun `test a bare WRMHEADER yields its key ids`() {
        val pssh = PSSH(header().encodeToUtf16LE())

        assertContentEquals(PSSH.PLAYREADY_SYSTEM_ID, pssh.initData.let { PSSH.PLAYREADY_SYSTEM_ID })
        assertEquals(listOf(kid), pssh.keyIds())
        assertEquals(listOf(header()), pssh.wrmHeaders())
    }

    @Test
    fun `test a bare PlayReady object record yields its key ids`() {
        val value = header().encodeToUtf16LE()
        val record = Buffer().apply {
            writeShortLe(0x01)
            writeShortLe(value.size)
            write(value)
        }.readByteArray()

        assertEquals(listOf(kid), PSSH(record).keyIds())
    }

    @Test
    fun `test a full PlayReady object is stored untouched`() {
        val pro = proOf(0x01 to header().encodeToUtf16LE())
        val pssh = PSSH(pro)

        assertContentEquals(pro, pssh.initData)
        assertEquals(listOf(kid), pssh.keyIds())
    }

    @Test
    fun `test every header record in an object is returned`() {
        val pro = proOf(
            0x01 to header().encodeToUtf16LE(),
            0x03 to byteArrayOf(1, 2, 3, 4),
            0x01 to header(listOf(secondKid)).encodeToUtf16LE(),
        )

        val headers = PSSH(pro).wrmHeaders()
        assertEquals(2, headers.size, "the embedded license store record should be skipped")
        assertEquals(header(), headers[0])
        assertEquals(header(listOf(secondKid)), headers[1])
    }

    @Test
    fun `test a header carries its algorithm and checksum through`() {
        val xml = "<WRMHEADER xmlns=\"${PlayreadyHeader.NAMESPACE}\" version=\"4.3.0.0\"><DATA>" +
            "<PROTECTINFO><KIDS>" +
            "<KID ALGID=\"AESCTR\" CHECKSUM=\"S0xqM1F6UVA=\" VALUE=\"RDMiEWZViHeZqrvM3e7/AA==\"></KID>" +
            "</KIDS></PROTECTINFO></DATA></WRMHEADER>"

        val parsed = PlayreadyHeader.parse(xml)
        val signed = parsed.signedKeyIds.single()

        assertEquals(kid, signed.value)
        assertEquals("AESCTR", signed.algId)
        assertEquals(8, signed.checksum?.size)
        assertEquals(xml, parsed.raw)
    }

    @Test
    fun `test a v4 0 0 0 header takes its algorithm and checksum from the document`() {
        val xml = "<WRMHEADER xmlns=\"${PlayreadyHeader.NAMESPACE}\" version=\"4.0.0.0\"><DATA>" +
            "<PROTECTINFO><KEYLEN>16</KEYLEN><ALGID>AESCTR</ALGID></PROTECTINFO>" +
            "<KID>RDMiEWZViHeZqrvM3e7/AA==</KID>" +
            "<CHECKSUM>S0xqM1F6UVA=</CHECKSUM>" +
            "</DATA></WRMHEADER>"

        val signed = PlayreadyHeader.parse(xml).signedKeyIds.single()

        assertEquals(kid, signed.value)
        assertEquals("AESCTR", signed.algId)
        assertEquals(8, signed.checksum?.size)
    }

    @Test
    fun `test wrmHeaders refuses a Widevine box`() {
        val pssh = PSSH(PSSH.new(systemId = PSSH.WIDEVINE.toUUID(), keyIds = listOf(kid)).export())
        assertFailsWith<ValueException> { pssh.wrmHeaders() }
    }

    @Test
    fun `test an oversized bare header is rejected rather than truncated`() {
        // The PlayReady record length field is a u16, so a header past 65535 bytes cannot be framed.
        val padding = "x".repeat(70_000)
        val xml = "<WRMHEADER xmlns=\"${PlayreadyHeader.NAMESPACE}\" version=\"4.3.0.0\"><DATA>" +
            "<PROTECTINFO><KIDS><KID ALGID=\"AESCTR\" VALUE=\"RDMiEWZViHeZqrvM3e7/AA==\"></KID></KIDS></PROTECTINFO>" +
            "<LA_URL>$padding</LA_URL></DATA></WRMHEADER>"

        assertFailsWith<ValueException> { PSSH(xml.encodeToUtf16LE()) }
    }

    @Test
    fun `test the key ids survive a round trip through a rebuilt object`() {
        val pssh = PSSH(header().encodeToUtf16LE())
        pssh.setKeyIds(listOf(secondKid))

        assertEquals(listOf(secondKid), pssh.keyIds())
        assertTrue(pssh.wrmHeaders().single().contains("WRMHEADER"))
    }
}
