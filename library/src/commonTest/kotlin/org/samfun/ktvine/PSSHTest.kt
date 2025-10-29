package org.samfun.ktvine

import kotlin.test.Test
import kotlin.test.assertEquals
import org.samfun.ktvine.proto.WidevinePsshData
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.utils.encodeToUtf16LE
import org.samfun.ktvine.utils.toByteArray
import org.samfun.ktvine.utils.toLEU16
import org.samfun.ktvine.utils.toLEU32
import java.util.UUID
import kotlin.io.encoding.Base64

class PSSHTest {

    private val WV_UUID: UUID = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    private fun wvData(vararg kids: UUID): WidevinePsshData =
        WidevinePsshData(key_ids = kids.map { it.toByteArray().toByteString() })

    private fun makeProXmlV43(vararg kids: UUID, withExtras: Boolean = false): ByteArray {
        val keyIdsXml = kids.joinToString("") { kid ->
            val b64 = Base64.encode(kid.toByteArray())
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

        val pssh = PSSH(pro)
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
    fun `test key ids from widevine header`() {
        val kid = UUID.randomUUID()
        val header = WidevinePsshData(key_ids = listOf(kid.toByteArray().toByteString()))
        val pssh = PSSH(header.encode())

        val kids = pssh.keyIds()
        assertEquals(1, kids.size)
        assertEquals(kid, kids.first())
    }
}
