package org.samfun.ktvine

import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.toLittleEndianByteArray
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * The header is parsed as XML rather than with regexes, so these cover the cases a regex
 * gets wrong: version-specific key id paths, quoting, entities, comments and stray
 * elements that merely look like the real thing.
 */
class PlayreadyHeaderTest {

    private val kid1 = Uuid.parse("d9008212-385b-3280-b3b2-f60df62a033e")
    private val kid2 = Uuid.parse("01234567-89ab-cdef-0123-456789abcdef")

    private fun le(kid: Uuid) = Base64.encode(kid.toLittleEndianByteArray())

    private fun wrap(version: String, body: String, declaration: Boolean = false) =
        (if (declaration) "<?xml version=\"1.0\" encoding=\"utf-16\"?>" else "") +
            "<WRMHEADER xmlns=\"${PlayreadyHeader.NAMESPACE}\" version=\"$version\">$body</WRMHEADER>"

    @Test
    fun `test v4_0_0_0 reads the key id from the element text`() {
        val xml = wrap(
            "4.0.0.0",
            "<DATA><PROTECTINFO><KEYLEN>16</KEYLEN><ALGID>AESCTR</ALGID></PROTECTINFO>" +
                "<KID>${le(kid1)}</KID><CHECKSUM>SsZ3HWI+w1Q=</CHECKSUM></DATA>",
        )

        val header = PlayreadyHeader.parse(xml)
        assertEquals("4.0.0.0", header.version)
        assertEquals(listOf(kid1), header.keyIds)
        assertEquals("AESCTR", header.algid, "v4.0.0.0 carries a document-level ALGID")
    }

    @Test
    fun `test v4_1_0_0 reads the key id from PROTECTINFO KID`() {
        val xml = wrap(
            "4.1.0.0",
            "<DATA><PROTECTINFO><KID ALGID=\"AESCTR\" CHECKSUM=\"x\" VALUE=\"${le(kid1)}\"></KID>" +
                "</PROTECTINFO></DATA>",
        )

        val header = PlayreadyHeader.parse(xml)
        assertEquals(listOf(kid1), header.keyIds)
        assertEquals("AESCTR", header.algid)
    }

    @Test
    fun `test v4_3_0_0 reads every key id from PROTECTINFO KIDS`() {
        val xml = wrap(
            "4.3.0.0",
            "<DATA><PROTECTINFO><KIDS>" +
                "<KID ALGID=\"AESCBC\" VALUE=\"${le(kid1)}\"></KID>" +
                "<KID ALGID=\"AESCBC\" VALUE=\"${le(kid2)}\"></KID>" +
                "</KIDS></PROTECTINFO></DATA>",
        )

        val header = PlayreadyHeader.parse(xml)
        assertEquals(listOf(kid1, kid2), header.keyIds)
        assertEquals("AESCBC", header.algid)
    }

    @Test
    fun `test a KID in the wrong place for the version is ignored`() {
        // A path-agnostic regex would pick this up and report a key that is not there.
        val xml = wrap(
            "4.3.0.0",
            "<DATA><PROTECTINFO><KIDS><KID ALGID=\"AESCTR\" VALUE=\"${le(kid1)}\"></KID></KIDS>" +
                "</PROTECTINFO>" +
                "<CUSTOMATTRIBUTES xmlns=\"\"><KID VALUE=\"${le(kid2)}\"></KID></CUSTOMATTRIBUTES></DATA>",
        )

        assertEquals(
            listOf(kid1),
            PlayreadyHeader.parse(xml).keyIds,
            "only the version's own KID path counts",
        )
    }

    @Test
    fun `test an xml declaration does not shadow the header version`() {
        val xml = wrap(
            "4.3.0.0",
            "<DATA><PROTECTINFO><KIDS><KID VALUE=\"${le(kid1)}\"></KID></KIDS></PROTECTINFO></DATA>",
            declaration = true,
        )

        assertEquals("4.3.0.0", PlayreadyHeader.parse(xml).version)
    }

    @Test
    fun `test single-quoted attributes comments and whitespace are handled`() {
        val xml = "<WRMHEADER xmlns='${PlayreadyHeader.NAMESPACE}' version='4.3.0.0'>" +
            "<!-- a packager comment --> \n " +
            "<DATA>\n  <PROTECTINFO>\n    <KIDS>\n" +
            "      <KID ALGID='AESCTR' VALUE='${le(kid1)}' />\n" +
            "    </KIDS>\n  </PROTECTINFO>\n" +
            "  <LA_URL>\n    https://ls.example.com/rights\n  </LA_URL>\n" +
            "</DATA></WRMHEADER>"

        val header = PlayreadyHeader.parse(xml)
        assertEquals(listOf(kid1), header.keyIds, "single-quoted attributes must parse")
        assertEquals("https://ls.example.com/rights", header.laUrl, "surrounding whitespace should be trimmed")
    }

    @Test
    fun `test entities in a url are decoded`() {
        val xml = wrap(
            "4.3.0.0",
            "<DATA><PROTECTINFO><KIDS><KID VALUE=\"${le(kid1)}\"></KID></KIDS></PROTECTINFO>" +
                "<LA_URL>https://ls.example.com/rights?a=1&amp;b=2&amp;c=&lt;3</LA_URL></DATA>",
        )

        assertEquals("https://ls.example.com/rights?a=1&b=2&c=<3", PlayreadyHeader.parse(xml).laUrl)
    }

    @Test
    fun `test build and parse round trip preserves every field`() {
        val built = PlayreadyHeader.build(
            keyIds = listOf(kid1, kid2),
            algid = "AESCBC",
            laUrl = "https://ls.example.com/rights?a=1&b=2",
            luiUrl = "https://ui.example.com/\"quoted\"",
            dsId = byteArrayOf(1, 2, 3, 4),
            decryptorSetup = "ONDEMAND",
            customAttributes = "<tag k=\"v\">text</tag>",
        )

        val header = PlayreadyHeader.parse(built)
        assertEquals(PlayreadyHeader.GENERATED_VERSION, header.version)
        assertEquals(listOf(kid1, kid2), header.keyIds)
        assertEquals("AESCBC", header.algid)
        assertEquals("https://ls.example.com/rights?a=1&b=2", header.laUrl, "the & must survive exactly once")
        assertEquals("https://ui.example.com/\"quoted\"", header.luiUrl)
        assertContentEquals(byteArrayOf(1, 2, 3, 4), header.dsId)
        assertEquals("ONDEMAND", header.decryptorSetup)
        assertEquals("<tag k=\"v\">text</tag>", header.customAttributes)
    }

    @Test
    fun `test generated output is deterministic`() {
        val args = listOf(kid1, kid2)
        val first = PlayreadyHeader.build(keyIds = args, algid = "AESCTR", laUrl = "https://a.example/x?y=1&z=2")
        val second = PlayreadyHeader.build(keyIds = args, algid = "AESCTR", laUrl = "https://a.example/x?y=1&z=2")
        assertEquals(first, second, "the same inputs must produce byte-identical XML")
        assertTrue(first.startsWith("<WRMHEADER "), first)
    }

    @Test
    fun `test absent optional fields stay absent`() {
        val built = PlayreadyHeader.build(keyIds = listOf(kid1), algid = "AESCTR")

        assertTrue("null" !in built, "no null literals may leak into the header: $built")
        assertTrue("LA_URL" !in built)
        val header = PlayreadyHeader.parse(built)
        assertNull(header.laUrl)
        assertNull(header.luiUrl)
        assertNull(header.dsId)
        assertNull(header.decryptorSetup)
        assertNull(header.customAttributes)
    }

    @Test
    fun `test malformed and unsupported headers are rejected`() {
        assertFailsWith<ValueException> { PlayreadyHeader.parse("<WRMHEADER version=\"4.3.0.0\">") }

        val noVersion = "<WRMHEADER xmlns=\"${PlayreadyHeader.NAMESPACE}\"><DATA></DATA></WRMHEADER>"
        assertFailsWith<ValueException> { PlayreadyHeader.parse(noVersion) }

        val badVersion = assertFailsWith<ValueException> {
            PlayreadyHeader.parse(wrap("9.9.9.9", "<DATA></DATA>"))
        }
        assertTrue(badVersion.message!!.contains("9.9.9.9"), badVersion.message!!)

        val shortKid = wrap(
            "4.3.0.0",
            "<DATA><PROTECTINFO><KIDS><KID VALUE=\"AAAA\"></KID></KIDS></PROTECTINFO></DATA>",
        )
        assertFailsWith<ValueException> { PlayreadyHeader.parse(shortKid) }
    }

    @Test
    fun `test a header with no key ids parses to an empty list`() {
        val header = PlayreadyHeader.parse(wrap("4.3.0.0", "<DATA><PROTECTINFO><KIDS></KIDS></PROTECTINFO></DATA>"))
        assertEquals(emptyList(), header.keyIds)
    }
}
