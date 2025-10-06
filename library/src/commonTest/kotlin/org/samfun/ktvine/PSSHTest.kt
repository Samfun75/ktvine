package org.samfun.ktvine

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertContentEquals
import org.samfun.ktvine.proto.WidevinePsshData
import okio.ByteString.Companion.toByteString
import java.util.Base64
import java.util.UUID

class PSSHTest {

    private val WV_UUID: UUID = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed")

    private val rawData = "AAAAoXBzc2gAAAAA7e+LqXnWSs6jyCfc1R0h7QAAAIEIARIQuLuP/+zYM2Ga0s2MA9iIKBoIY2FzdGxhYnMiWGV5SmhjM05sZEVsa0lqb2laRGhoTURoaU5HVXpaamxoTTJVM01qZzRPVGRpWlRNNU5ETXdaV05oTURBaUxDSjJZWEpwWVc1MFNXUWlPaUpoZG10bGVTSjkyB2RlZmF1bHQ="

    private fun wvData(vararg kids: UUID): WidevinePsshData =
        WidevinePsshData(key_ids = kids.map { it.toByteArray().toByteString() })

    private fun makeProXmlV43(vararg kids: UUID, withExtras: Boolean = false): ByteArray {
        val keyIdsXml = kids.joinToString("") { kid ->
            val b64 = Base64.getEncoder().encodeToString(kid.toByteArray())
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
        """.trimIndent().toByteArray(Charsets.UTF_16LE)
        return xml
    }

    private fun proWrapSingleRecord(prHeaderUtf16Le: ByteArray): ByteArray {
        val recordCount = leU16(1)
        val type = leU16(0x01)
        val len = leU16(prHeaderUtf16Le.size)
        val body = recordCount + type + len + prHeaderUtf16Le
        val size = leU32(body.size + 4)
        return size + body
    }

    private fun leU16(v: Int): ByteArray = byteArrayOf((v and 0xFF).toByte(), ((v ushr 8) and 0xFF).toByte())
    private fun leU32(v: Int): ByteArray = byteArrayOf(
        (v and 0xFF).toByte(),
        ((v ushr 8) and 0xFF).toByte(),
        ((v ushr 16) and 0xFF).toByte(),
        ((v ushr 24) and 0xFF).toByte()
    )

    @Test
    fun testWidevineV0KeyIdsRoundTrip() {
        val k1 = UUID.fromString("11111111-2222-3333-4444-555555555555")
        val k2 = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
        val data = wvData(k1, k2)

        val pssh = PSSH.new(
            system_id = WV_UUID,
            init_data = data,
            version = 0
        )
        assertEquals(setOf(k1, k2), pssh.key_ids().toSet())

        val b64 = pssh.dumps()
        val pssh2 = PSSH(b64)
        assertEquals(setOf(k1, k2), pssh2.key_ids().toSet())

        // Ensure dump is an MP4 PSSH box the parser can read
        val parsed = PSSH(pssh.dump())
        assertEquals(setOf(k1, k2), parsed.key_ids().toSet())
    }

    @Test
    fun testPlayReadyParsingAndToWidevine() {
        val k1 = UUID.fromString("01234567-89ab-cdef-0123-456789abcdef")
        val k2 = UUID.fromString("00112233-4455-6677-8899-aabbccddeeff")
        val xml = makeProXmlV43(k1, k2)
        val pro = proWrapSingleRecord(xml)

        val pssh = PSSH(pro)
        assertEquals(setOf(k1, k2), pssh.key_ids().toSet())

        pssh.to_widevine()
        assertEquals(setOf(k1, k2), pssh.key_ids().toSet())

        // After conversion, dump and reparse should preserve KIDs
        val reparsed = PSSH(pssh.dump())
        assertEquals(setOf(k1, k2), reparsed.key_ids().toSet())
    }

    @Test
    fun testWidevineToPlayReadyAndBack() {
        val k1 = UUID.fromString("fedcba98-7654-3210-fedc-ba9876543210")
        val data = wvData(k1)
        val pssh = PSSH.new(system_id = WV_UUID, init_data = data, version = 0)

        pssh.to_playready(la_url = "https://license.example.com")
        assertEquals(setOf(k1), pssh.key_ids().toSet())

        // Convert back to WV
        pssh.to_widevine()
        assertEquals(setOf(k1), pssh.key_ids().toSet())
    }

    @Test
    fun testSetKeyIdsVersion1() {
        val k1 = UUID.fromString("00000000-0000-0000-0000-000000000001")
        val k2 = UUID.fromString("00000000-0000-0000-0000-000000000002")
        val k3 = UUID.fromString("00000000-0000-0000-0000-000000000003")

        val pssh = PSSH.new(system_id = WV_UUID, key_ids = listOf(k1), version = 1)
        assertEquals(listOf(k1), pssh.key_ids())

        pssh.set_key_ids(listOf(k2, k3))
        assertEquals(listOf(k2, k3), pssh.key_ids())

        // WV header content should contain k2,k3 as well
        val reparsed = PSSH(pssh.dump())
        assertEquals(listOf(k2, k3), reparsed.key_ids())
    }

    @Test
    fun keyIds_fromWidevineHeader() {
        val kid = UUID.randomUUID()
        val header = WidevinePsshData(key_ids = listOf(kid.toByteArray().toByteString()))
        val pssh = PSSH(header.encode())

        val kids = pssh.key_ids()
        assertEquals(1, kids.size)
        assertEquals(kid, kids.first())
    }
}
