package org.samfun.ktvine

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import org.samfun.ktvine.proto.WidevinePsshData
import okio.Buffer
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.utils.decodeToStringUtf16LE
import org.samfun.ktvine.utils.encodeToUtf16LE
import org.samfun.ktvine.utils.toByteArray
import org.samfun.ktvine.utils.toLittleEndianByteArray
import org.samfun.ktvine.utils.toLEU16
import org.samfun.ktvine.utils.toLEU32
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.toUUID
import java.util.UUID
import kotlin.io.encoding.Base64

class PSSHTest {

    private val WV_UUID: UUID = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    private fun wvData(vararg kids: UUID): WidevinePsshData =
        WidevinePsshData(key_ids = kids.map { it.toByteArray().toByteString() })

    private fun makeProXmlV43(vararg kids: UUID, withExtras: Boolean = false): ByteArray {
        val keyIdsXml = kids.joinToString("") { kid ->
            // Real PlayReady headers carry little-endian GUIDs.
            val b64 = Base64.encode(kid.toLittleEndianByteArray())
            """
            <KID ALGID="AESCTR" VALUE="$b64"></KID>
            """.trimIndent()
        }
        val extras = if (withExtras) {
            """
            <LA_URL>https://license.example.com</LA_URL>
            <LUI_URL>https://ui.example.com</LUI_URL>
            <DECRYPTORSETUP>ONDEMAND</DECRYPTORSETUP>
            <CUSTOMATTRIBUTES xmlns="">k=v</CUSTOMATTRIBUTES>
            """.trimIndent()
        } else ""

        val xml = """
        <WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.3.0.0">
            <DATA>
                <PROTECTINFO>
                    <KIDS>$keyIdsXml</KIDS>
                </PROTECTINFO>
                $extras
            </DATA>
        </WRMHEADER>
        """.trimIndent().encodeToUtf16LE()
        return xml
    }

    /** Unwrap a PRO and return its record-type 0x01 PlayReady header as text. */
    private fun readPlayreadyHeader(pro: ByteArray): String {
        val buf = Buffer().write(pro)
        assertEquals(pro.size, buf.readIntLe(), "PRO length prefix does not match its own size")
        val recordCount = buf.readShortLe().toInt() and 0xFFFF
        repeat(recordCount) {
            val type = buf.readShortLe().toInt() and 0xFFFF
            val length = buf.readShortLe().toInt() and 0xFFFF
            val value = buf.readByteArray(length.toLong())
            if (type == 0x01) return value.decodeToStringUtf16LE()
        }
        error("No PlayReadyHeader record in PRO")
    }

    /** Same header, prefixed with the XML declaration many packagers emit. */
    private fun makeProXmlV43WithDeclaration(vararg kids: UUID): ByteArray {
        val declared = "<?xml version=" + '"'.toString() + "1.0" + '"'.toString() +
            " encoding=" + '"'.toString() + "utf-16" + '"'.toString() + "?>"
        return (declared + makeProXmlV43(*kids).decodeToStringUtf16LE()).encodeToUtf16LE()
    }

    private fun proWrapSingleRecord(prHeaderUtf16Le: ByteArray): ByteArray {
        val recordCount = 1.toLEU16()
        val type = (0x01).toLEU16()
        val len = prHeaderUtf16Le.size.toLEU16()
        val body = recordCount + type + len + prHeaderUtf16Le
        val size = (body.size + 4).toLEU32()
        return size + body
    }

    @Test
    fun `test widevine v0 key ids round trip`() {
        val k1 = UUID.fromString("11111111-2222-3333-4444-555555555555")
        val k2 = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        val data = wvData(k1, k2)

        val pssh = PSSH.new(
            systemId = WV_UUID,
            initData = data,
            version = 0
        )
        assertEquals(setOf(k1, k2), pssh.keyIds().toSet())

        val b64 = pssh.exportBase64()
        val pssh2 = PSSH(b64)
        assertEquals(setOf(k1, k2), pssh2.keyIds().toSet())

        // Ensure dump is an MP4 PSSH box the parser can read
        val parsed = PSSH(pssh.export())
        assertEquals(setOf(k1, k2), parsed.keyIds().toSet())
    }

    @Test
    fun `test play ready parsing and to widevine`() {
        val k1 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")
        val k2 = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val xml = makeProXmlV43(k1, k2)
        val pro = proWrapSingleRecord(xml)

        val pssh = PSSH.new(systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(), initData = pro)
        assertEquals(setOf(k1, k2), pssh.keyIds().toSet())

        pssh.toWidevine()
        assertEquals(setOf(k1, k2), pssh.keyIds().toSet())

        // After conversion, dump and reparse should preserve KIDs
        val reparsed = PSSH(pssh.export())
        assertEquals(setOf(k1, k2), reparsed.keyIds().toSet())
    }

    @Test
    fun `test widevine to play ready and back`() {
        val k1 = UUID.fromString("fedcba98-7654-3210-fedc-ba9876543210")
        val data = wvData(k1)
        val pssh = PSSH.new(systemId = WV_UUID, initData = data, version = 0)

        pssh.toPlayready(laUrl = "https://license.example.com")
        assertEquals(setOf(k1), pssh.keyIds().toSet())

        // Convert back to WV
        pssh.toWidevine()
        assertEquals(setOf(k1), pssh.keyIds().toSet())
    }

    @Test
    fun `test set key ids version1`() {
        val k1 = UUID.fromString("00000000-0000-0000-0000-000000000001")
        val k2 = UUID.fromString("00000000-0000-0000-0000-000000000002")
        val k3 = UUID.fromString("00000000-0000-0000-0000-000000000003")

        val pssh = PSSH.new(systemId = WV_UUID, keyIds = listOf(k1), version = 1)
        assertEquals(listOf(k1), pssh.keyIds())

        pssh.setKeyIds(listOf(k2, k3))
        assertEquals(listOf(k2, k3), pssh.keyIds())

        // WV header content should contain k2,k3 as well
        val reparsed = PSSH(pssh.export())
        assertEquals(listOf(k2, k3), reparsed.keyIds())
    }

    @Test
    fun `test to play ready omits absent optional fields`() {
        val k1 = UUID.fromString("fedcba98-7654-3210-fedc-ba9876543210")
        val pssh = PSSH.new(systemId = WV_UUID, initData = wvData(k1), version = 0)

        pssh.toPlayready()

        val xml = readPlayreadyHeader(pssh.initData)
        assertFalse(xml.contains("null"), "Generated PlayReady header leaked a null literal: $xml")
        assertFalse(xml.contains("<LA_URL>"), "LA_URL emitted despite being absent: $xml")
        assertFalse(xml.contains("<LUI_URL>"), "LUI_URL emitted despite being absent: $xml")
        assertFalse(xml.contains("<DS_ID>"), "DS_ID emitted despite being absent: $xml")
        assertFalse(xml.contains("<DECRYPTORSETUP>"), "DECRYPTORSETUP emitted despite being absent: $xml")
        assertFalse(xml.contains("<CUSTOMATTRIBUTES"), "CUSTOMATTRIBUTES emitted despite being absent: $xml")

        assertEquals(setOf(k1), pssh.keyIds().toSet())
    }

    @Test
    fun `test to play ready emits present optional fields`() {
        val k1 = UUID.fromString("fedcba98-7654-3210-fedc-ba9876543210")
        val pssh = PSSH.new(systemId = WV_UUID, initData = wvData(k1), version = 0)

        pssh.toPlayready(
            laUrl = "https://license.example.com",
            luiUrl = "https://ui.example.com",
            dsId = byteArrayOf(1, 2, 3, 4),
            decryptorSetup = "ONDEMAND",
            customData = "<tag>v</tag>"
        )

        val xml = readPlayreadyHeader(pssh.initData)
        assertFalse(xml.contains("null"), "Generated PlayReady header leaked a null literal: $xml")
        assertTrue(xml.contains("<LA_URL>https://license.example.com</LA_URL>"), xml)
        assertTrue(xml.contains("<LUI_URL>https://ui.example.com</LUI_URL>"), xml)
        assertTrue(xml.contains("<DS_ID>${Base64.encode(byteArrayOf(1, 2, 3, 4))}</DS_ID>"), xml)
        assertTrue(xml.contains("<DECRYPTORSETUP>ONDEMAND</DECRYPTORSETUP>"), xml)
        assertTrue(xml.contains("<CUSTOMATTRIBUTES xmlns=\"\"><tag>v</tag></CUSTOMATTRIBUTES>"), xml)
    }

    @Test
    fun `test key ids from widevine header`() {
        val kid = UUID.randomUUID()
        val header = WidevinePsshData(key_ids = listOf(kid.toByteArray().toByteString()))
        val pssh = PSSH.new(systemId = WV_UUID, initData = header.encode())

        val kids = pssh.keyIds()
        assertEquals(1, kids.size)
        assertEquals(kid, kids.first())
    }

    @Test
    fun `test play ready header parses despite an xml declaration`() {
        val k1 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")
        val pro = proWrapSingleRecord(makeProXmlV43WithDeclaration(k1))
        val pssh = PSSH.new(systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(), initData = pro)

        // An unanchored version regex matches the declaration's version="1.0" first and
        // then rejects the header as an unsupported version.
        assertEquals(setOf(k1), pssh.keyIds().toSet())
    }

    @Test
    fun `test to play ready escapes urls with query strings`() {
        val k1 = UUID.fromString("fedcba98-7654-3210-fedc-ba9876543210")
        val pssh = PSSH.new(systemId = WV_UUID, initData = wvData(k1), version = 0)

        // A bare & here produces XML that will not parse.
        pssh.toPlayready(
            laUrl = "https://ls.example.com/rights?a=1&b=2",
            decryptorSetup = "<not a tag>"
        )

        val xml = readPlayreadyHeader(pssh.initData)
        assertTrue(
            xml.contains("<LA_URL>https://ls.example.com/rights?a=1&amp;b=2</LA_URL>"),
            xml
        )
        assertTrue(xml.contains("<DECRYPTORSETUP>&lt;not a tag&gt;</DECRYPTORSETUP>"), xml)
        assertFalse(
            Regex("&(?!amp;|lt;|gt;|quot;|apos;)").containsMatchIn(xml),
            "an unescaped & escaped into the header: " + xml
        )

        // The KIDs must still survive the escaping pass.
        assertEquals(setOf(k1), pssh.keyIds().toSet())
    }

    @Test
    fun `test to play ready rejects a header over the record size limit`() {
        val k1 = UUID.fromString("fedcba98-7654-3210-fedc-ba9876543210")
        val pssh = PSSH.new(systemId = WV_UUID, initData = wvData(k1), version = 0)

        // u16 record length: silently truncating here produced a corrupt PRO.
        assertFailsWith<ValueException> { pssh.toPlayready(laUrl = "x".repeat(40_000)) }
    }

    @Test
    fun `test corrupt playready object reports why`() {
        // Size prefix disagrees with the actual length.
        val corrupt = 999.toLEU32() + 1.toLEU16() + (0x01).toLEU16() + 0.toLEU16()
        val pssh = PSSH.new(systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(), initData = corrupt)

        val failure = assertFailsWith<ValueException> { pssh.keyIds() }
        assertTrue(
            failure.message!!.contains("corrupt"),
            "expected a corrupt-PRO message, got: " + failure.message
        )
    }

    @Test
    fun `test playready object without a header record reports why`() {
        // One record, but of type 0x03 (Embedded License Store) rather than the header.
        val body = 1.toLEU16() + (0x03).toLEU16() + 0.toLEU16()
        val pro = (body.size + 4).toLEU32() + body
        val pssh = PSSH.new(systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(), initData = pro)

        val failure = assertFailsWith<ValueException> { pssh.keyIds() }
        assertTrue(
            failure.message!!.contains("no PlayReadyHeader"),
            "expected a missing-header message, got: " + failure.message
        )
    }

    @Test
    fun `test unsupported playready version is not swallowed`() {
        val xml = ("<WRMHEADER version=" + '"'.toString() + "9.9.9.9" + '"'.toString() +
            "><DATA></DATA></WRMHEADER>").encodeToUtf16LE()
        val pssh = PSSH.new(
            systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(),
            initData = proWrapSingleRecord(xml)
        )

        val failure = assertFailsWith<ValueException> { pssh.keyIds() }
        assertTrue(
            failure.message!!.contains("9.9.9.9"),
            "the specific version error used to be swallowed into a generic message, got: " + failure.message
        )
    }

    @Test
    fun `test bare widevine cenc header is accepted`() {
        val k1 = UUID.fromString("11111111-2222-3333-4444-555555555555")
        val header = wvData(k1).encode()

        val pssh = PSSH(header)

        assertEquals(setOf(k1), pssh.keyIds().toSet())
        assertContentEquals(header, pssh.initData, "the header must be stored verbatim")
        // It becomes a real box on the way out.
        assertEquals(setOf(k1), PSSH(pssh.export()).keyIds().toSet())
    }

    @Test
    fun `test bare playready object is accepted`() {
        val k1 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")
        val pro = proWrapSingleRecord(makeProXmlV43(k1))

        val pssh = PSSH(pro)

        assertEquals(setOf(k1), pssh.keyIds().toSet())
        assertContentEquals(pro, pssh.initData)
    }

    @Test
    fun `test unrecognised init data is wrapped in lenient mode and rejected in strict mode`() {
        // Netflix MSL and similar send init data no standard header describes.
        val custom = byteArrayOf(-1, -2, -3, -4, -5, -6, -7, -8)

        val lenient = PSSH(custom)
        assertContentEquals(custom, lenient.initData)

        assertFailsWith<DecodeException> { PSSH(custom, strict = true) }
    }

    @Test
    fun `test empty input is rejected`() {
        assertFailsWith<ValueException> { PSSH(ByteArray(0)) }
    }

    @Test
    fun `test parseAll returns every box in a multi-DRM segment`() {
        val k1 = UUID.fromString("11111111-2222-3333-4444-555555555555")
        val k2 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")

        val widevine = PSSH.new(systemId = WV_UUID, initData = wvData(k1), version = 0)
        val playready = PSSH.new(
            systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(),
            initData = proWrapSingleRecord(makeProXmlV43(k2))
        )
        val segment = widevine.export() + playready.export()

        val all = PSSH.parseAll(segment)
        assertEquals(2, all.size, "both boxes must be returned")
        assertEquals(setOf(k1), all[0].keyIds().toSet())
        assertEquals(setOf(k2), all[1].keyIds().toSet())

        // The constructors keep taking only the first.
        assertEquals(setOf(k1), PSSH(segment).keyIds().toSet())
    }

    @Test
    fun `test fromInitSegment selects by system id`() {
        val k1 = UUID.fromString("11111111-2222-3333-4444-555555555555")
        val k2 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")

        val widevine = PSSH.new(systemId = WV_UUID, initData = wvData(k1), version = 0)
        val playready = PSSH.new(
            systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(),
            initData = proWrapSingleRecord(makeProXmlV43(k2))
        )
        val segment = playready.export() + widevine.export()

        assertEquals(
            setOf(k1),
            PSSH.fromInitSegment(segment)!!.keyIds().toSet(),
            "must pick the Widevine box even though PlayReady comes first"
        )
        assertEquals(
            setOf(k2),
            PSSH.fromInitSegment(segment, PSSH.PLAYREADY_SYSTEM_ID)!!.keyIds().toSet()
        )
        assertNull(PSSH.fromInitSegment(widevine.export(), PSSH.PLAYREADY_SYSTEM_ID))
    }

    @Test
    fun `test a non-default encryption scheme is preserved both ways`() {
        val k1 = UUID.fromString("fedcba98-7654-3210-fedc-ba9876543210")
        val cbc = WidevinePsshData(
            key_ids = listOf(k1.toByteArray().toByteString()),
            protection_scheme = 0x63626331 // 'cbc1'
        )
        val pssh = PSSH.new(systemId = WV_UUID, initData = cbc, version = 0)
        assertEquals("AESCBC", pssh.encryptionScheme)

        pssh.toPlayready()
        assertTrue(
            readPlayreadyHeader(pssh.initData).contains("ALGID=\"AESCBC\""),
            "toPlayready hardcoded AESCTR: " + readPlayreadyHeader(pssh.initData)
        )
        assertEquals("AESCBC", pssh.encryptionScheme)

        pssh.toWidevine()
        assertEquals("AESCBC", pssh.encryptionScheme, "the scheme must survive the round trip")
        assertEquals(setOf(k1), pssh.keyIds().toSet())
    }

    @Test
    fun `test a header without a scheme reports null`() {
        val pssh = PSSH.new(
            systemId = WV_UUID,
            initData = WidevinePsshData(key_ids = listOf(UUID(0, 1).toByteArray().toByteString())),
            version = 0
        )
        assertNull(pssh.encryptionScheme)
    }

    @Test
    fun `test setKeyIds rewrites a playready header and keeps its other elements`() {
        val k1 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")
        val k2 = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val pssh = PSSH.new(systemId = WV_UUID, initData = wvData(k1), version = 0)
        pssh.toPlayready(laUrl = "https://ls.example.com/rights?a=1&b=2", decryptorSetup = "ONDEMAND")

        pssh.setKeyIds(listOf(k2))

        assertEquals(setOf(k2), pssh.keyIds().toSet())
        val xml = readPlayreadyHeader(pssh.initData)
        assertTrue(
            xml.contains("<LA_URL>https://ls.example.com/rights?a=1&amp;b=2</LA_URL>"),
            "LA_URL should survive a key id rewrite, and stay escaped exactly once: " + xml
        )
        assertTrue(xml.contains("<DECRYPTORSETUP>ONDEMAND</DECRYPTORSETUP>"), xml)
    }

    @Test
    fun `test new with playready system id and key ids builds a real PRO`() {
        val k1 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")

        val pssh = PSSH.new(
            systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(),
            keyIds = listOf(k1),
            version = 1
        )

        // This used to leave init_data empty, producing a box no PlayReady client accepts.
        assertTrue(pssh.initData.isNotEmpty(), "a PlayReady box needs a PlayReadyObject")
        assertTrue(readPlayreadyHeader(pssh.initData).contains("<WRMHEADER"), "expected a WRMHEADER")
        assertEquals(setOf(k1), PSSH(pssh.export()).keyIds().toSet())
    }

    @Test
    fun `test new with widevine system id and key ids builds a cenc header`() {
        val k1 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")
        val pssh = PSSH.new(systemId = WV_UUID, keyIds = listOf(k1), version = 1)

        assertTrue(pssh.initData.isNotEmpty(), "the CENC header should be populated too")
        assertEquals(setOf(k1), PSSH(pssh.export()).keyIds().toSet())
    }

    @Test
    fun `test setKeyIds still rejects an unknown system id`() {
        val other = UUID.fromString("11111111-1111-1111-1111-111111111111")
        val pssh = PSSH.new(systemId = other, initData = byteArrayOf(1, 2, 3))
        assertFailsWith<ValueException> { pssh.setKeyIds(listOf(UUID(0, 1))) }
    }
}
