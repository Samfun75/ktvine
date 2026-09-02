@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine

import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.encodeToUtf16LE
import org.samfun.ktvine.utils.toLEU16
import org.samfun.ktvine.utils.toLEU32
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * PlayReady header handling pinned against an independent implementation.
 *
 * Every header and every expected key id below was produced and verified with **pyplayready
 * 0.8.1** (`WRMHeader`, an unrelated real PlayReady implementation): it parsed each of these
 * exact documents and reported exactly these GUIDs. That is what makes this different from
 * [PlayreadyHeaderTest], which computes its expectations with `toLittleEndianByteArray` —
 * the same conversion it is testing, so it can only prove ktvine agrees with itself.
 *
 * The agreement also settles a documented divergence: ktvine byte-swaps PlayReady KIDs and
 * pywidevine does not. pyplayready swaps too (`UUID(bytes_le=...)`), so a second real
 * PlayReady stack confirms ktvine's direction is the correct one.
 */
class PlayreadyOracleTest {

    // --- pyplayready-verified fixtures (do not regenerate with ktvine helpers) ---

    private val k1 = Uuid.parse("9eb4050d-e44b-4802-932e-27d75083e266")
    private val k2 = Uuid.parse("0e5f3a1e-896e-ab55-2f76-1f73b75d0d1d")
    private val k3 = Uuid.parse("112233ff-4455-6677-8899-aabbccddeeff")

    /** pyplayready encoded k1 as this VALUE, i.e. base64 of its little-endian GUID bytes. */
    private val k1ValueLe = "DQW0nkvkAkiTLifXUIPiZg=="

    private val ns = "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader"

    private val v40 =
        "<WRMHEADER xmlns=\"$ns\" version=\"4.0.0.0\">" +
            "<DATA><PROTECTINFO><KEYLEN>16</KEYLEN><ALGID>AESCTR</ALGID></PROTECTINFO>" +
            "<KID>$k1ValueLe</KID><LA_URL>https://example.com/la</LA_URL></DATA></WRMHEADER>"

    private val v41 =
        "<WRMHEADER xmlns=\"$ns\" version=\"4.1.0.0\">" +
            "<DATA><PROTECTINFO><KID ALGID=\"AESCTR\" VALUE=\"$k1ValueLe\"></KID></PROTECTINFO></DATA></WRMHEADER>"

    private val v42 =
        "<WRMHEADER xmlns=\"$ns\" version=\"4.2.0.0\">" +
            "<DATA><PROTECTINFO><KIDS>" +
            "<KID ALGID=\"AESCTR\" VALUE=\"$k1ValueLe\"></KID>" +
            "<KID ALGID=\"AESCBC\" VALUE=\"HjpfDm6JVasvdh9zt10NHQ==\"></KID>" +
            "</KIDS></PROTECTINFO></DATA></WRMHEADER>"

    private val v43 =
        "<WRMHEADER xmlns=\"$ns\" version=\"4.3.0.0\">" +
            "<DATA><PROTECTINFO><KIDS>" +
            "<KID ALGID=\"AESCTR\" VALUE=\"$k1ValueLe\"></KID>" +
            "<KID ALGID=\"AESCTR\" VALUE=\"HjpfDm6JVasvdh9zt10NHQ==\"></KID>" +
            "<KID ALGID=\"AESCTR\" VALUE=\"/zMiEVVEd2aImaq7zN3u/w==\"></KID>" +
            "</KIDS></PROTECTINFO></DATA></WRMHEADER>"

    @Test
    fun `test v4_0_0_0 key id matches pyplayready`() {
        assertEquals(listOf(k1), PlayreadyHeader.parse(v40).keyIds)
    }

    @Test
    fun `test v4_1_0_0 key id matches pyplayready`() {
        assertEquals(listOf(k1), PlayreadyHeader.parse(v41).keyIds)
    }

    @Test
    fun `test v4_2_0_0 key ids match pyplayready`() {
        assertEquals(listOf(k1, k2), PlayreadyHeader.parse(v42).keyIds)
    }

    @Test
    fun `test v4_3_0_0 key ids match pyplayready`() {
        assertEquals(listOf(k1, k2, k3), PlayreadyHeader.parse(v43).keyIds)
    }

    /**
     * The build direction, checked against the same independent little-endian encoding rather
     * than by round-tripping through ktvine's own parser.
     */
    @Test
    fun `test ktvine emits the little-endian VALUE pyplayready expects`() {
        val built = PlayreadyHeader.build(keyIds = listOf(k1), algid = "AESCTR")
        assertTrue(
            "VALUE=\"$k1ValueLe\"" in built,
            "expected VALUE=\"$k1ValueLe\" (base64 of the LE GUID) in: $built",
        )
        // And it must read back as the same GUID.
        assertEquals(listOf(k1), PlayreadyHeader.parse(built).keyIds)
    }

    /**
     * A PRO may carry an Embedded License Store (record type 0x03) before the 0x01 header.
     * ktvine must skip the ELS and still find the KIDs, matching pyplayready's record loop.
     */
    @Test
    fun `test a pro with an embedded license store record before the header is still read`() {
        val header = PlayreadyHeader.build(keyIds = listOf(k1, k2), algid = "AESCTR").encodeToUtf16LE()
        val els = byteArrayOf(0x11, 0x22, 0x33, 0x44) // opaque ELS bytes; must be ignored

        val body = 2.toLEU16() + // record count
            (0x03).toLEU16() + els.size.toLEU16() + els + // ELS record, skipped
            (0x01).toLEU16() + header.size.toLEU16() + header // header record
        val pro = (body.size + 4).toLEU32() + body

        val pssh = PSSH.new(systemId = Uuid.parse("9a04f079-9840-4286-ab92-e65be0885f95"), initData = pro)
        assertEquals(listOf(k1, k2), pssh.keyIds())
    }
}
