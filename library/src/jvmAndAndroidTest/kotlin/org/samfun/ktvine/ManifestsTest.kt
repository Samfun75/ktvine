package org.samfun.ktvine

import org.samfun.ktvine.core.Manifests
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.utils.DecodeException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Manifest extraction against the real checked-in manifests, cross-checked against each
 * manifest's own `cenc:default_KID` rather than against ktvine's own output.
 */
class ManifestsTest {

    @Test
    fun `test widevine pssh is pulled out of a real mpd`() {
        val mpd = TestFixtures.readText("playlist/bitmovin.mpd")

        val boxes = Manifests.psshFromMpd(mpd)

        assertEquals(1, boxes.size, "the same ContentProtection repeats per AdaptationSet and must collapse")
        assertEquals(
            Manifests.defaultKeyIdsFromMpd(mpd),
            boxes[0].keyIds(),
            "the extracted PSSH must agree with the manifest's own default_KID",
        )
    }

    @Test
    fun `test playready pro is pulled out of a real mpd`() {
        val mpd = TestFixtures.readText("playlist/cr.mpd")

        val boxes = Manifests.psshFromMpd(mpd, PSSH.PLAYREADY_SYSTEM_ID)

        assertEquals(1, boxes.size)
        assertEquals(
            Manifests.defaultKeyIdsFromMpd(mpd),
            boxes[0].keyIds(),
            "an mspr:pro must yield the same KID the manifest declares",
        )
        assertEquals("AESCTR", boxes[0].encryptionScheme)
    }

    @Test
    fun `test asking for the wrong system returns nothing`() {
        // cr.mpd carries PlayReady only.
        assertEquals(emptyList(), Manifests.psshFromMpd(TestFixtures.readText("playlist/cr.mpd")))
        // bitmovin.mpd carries Widevine only.
        assertEquals(
            emptyList(),
            Manifests.psshFromMpd(TestFixtures.readText("playlist/bitmovin.mpd"), PSSH.PLAYREADY_SYSTEM_ID),
        )
    }

    @Test
    fun `test default key ids are read from a real mpd`() {
        assertEquals(
            listOf(Uuid.parse("eb676abb-cb34-5e96-bbcf-616630f1a3da")),
            Manifests.defaultKeyIdsFromMpd(TestFixtures.readText("playlist/bitmovin.mpd")),
        )
        assertEquals(
            listOf(Uuid.parse("d9008212-385b-3280-b3b2-f60df62a033e")),
            Manifests.defaultKeyIdsFromMpd(TestFixtures.readText("playlist/cr.mpd")),
        )
    }

    @Test
    fun `test a malformed mpd is reported as a decode error`() {
        assertFailsWith<DecodeException> { Manifests.psshFromMpd("<MPD><Period>") }
        assertFailsWith<DecodeException> { Manifests.defaultKeyIdsFromMpd("not xml at all <<<") }
    }

    @Test
    fun `test hls session keys carrying inline pssh are extracted`() {
        val pssh = PSSH.new(
            systemId = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"),
            keyIds = listOf(Uuid.parse("11111111-2222-3333-4444-555555555555")),
            version = 1,
        )
        val playlist = buildString {
            appendLine("#EXTM3U")
            // A comma inside the quoted URI is exactly what a naive split gets wrong.
            appendLine(
                "#EXT-X-SESSION-KEY:METHOD=SAMPLE-AES-CTR," +
                    "URI=\"data:text/plain;base64,${pssh.exportBase64()}\"," +
                    "KEYFORMAT=\"urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed\",KEYFORMATVERSIONS=\"1\"",
            )
            appendLine("#EXT-X-STREAM-INF:BANDWIDTH=1000")
            appendLine("v.m3u8")
        }

        val boxes = Manifests.psshFromM3u8(playlist)

        assertEquals(1, boxes.size)
        assertEquals(pssh.keyIds(), boxes[0].keyIds())
    }

    @Test
    fun `test hls keys for other systems and external uris are skipped`() {
        val playlist = buildString {
            appendLine("#EXTM3U")
            appendLine("#EXT-X-KEY:METHOD=NONE")
            // PlayReady, not Widevine.
            appendLine(
                "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"data:text/plain;base64,AAAA\"," +
                    "KEYFORMAT=\"urn:uuid:9a04f079-9840-4286-ab92-e65be0885f95\"",
            )
            // Widevine, but the key lives behind a URL we are not going to fetch.
            appendLine(
                "#EXT-X-KEY:METHOD=SAMPLE-AES,URI=\"https://keys.example.com/k1\"," +
                    "KEYFORMAT=\"urn:uuid:edef8ba9-79d6-4ace-a3c8-27dcd51d21ed\"",
            )
        }

        assertTrue(Manifests.psshFromM3u8(playlist).isEmpty())
    }

    @Test
    fun `test a playlist without keys yields nothing`() {
        assertEquals(emptyList(), Manifests.psshFromM3u8(TestFixtures.readText("playlist/bitmovin.m3u8")))
    }
}
