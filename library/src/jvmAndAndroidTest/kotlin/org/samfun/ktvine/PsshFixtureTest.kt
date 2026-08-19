package org.samfun.ktvine

import org.samfun.ktvine.core.PSSH
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * PSSH parsing against real manifests.
 *
 * Every expectation here comes from the manifest's own `cenc:default_KID`, never from
 * round-tripping ktvine's own output — `toPlayready` and `keyIds` were symmetrically wrong
 * about GUID byte order for a long time and round-tripped perfectly while doing it.
 */
class PsshFixtureTest {

    private fun psshFrom(manifest: String, tag: String): PSSH {
        val xml = TestFixtures.readText(manifest)
        val b64 = Regex("<$tag[^>]*>([^<]+)</$tag>")
            .find(xml)
            ?.groupValues?.get(1)
            ?.trim()
            ?: error("No <$tag> in $manifest")
        return PSSH(b64)
    }

    private fun defaultKidOf(manifest: String): String =
        Regex("""cenc:default_KID="([^"]+)"""")
            .find(TestFixtures.readText(manifest))
            ?.groupValues?.get(1)
            ?.lowercase()
            ?: error("No cenc:default_KID in $manifest")

    @Test
    fun `test playready pssh key id matches the manifest default KID`() {
        val manifest = "playlist/cr.mpd"
        val pssh = psshFrom(manifest, "cenc:pssh")

        assertEquals(
            listOf(defaultKidOf(manifest)),
            pssh.keyIds().map { it.toString() },
            "PlayReady stores KIDs as little-endian GUIDs; reading them big-endian yields " +
                "128200d9-5b38-8032-b3b2-f60df62a033e instead"
        )
    }

    @Test
    fun `test playready to widevine keeps the manifest default KID`() {
        val manifest = "playlist/cr.mpd"
        val pssh = psshFrom(manifest, "cenc:pssh")

        pssh.toWidevine()

        assertEquals(
            listOf(defaultKidOf(manifest)),
            pssh.keyIds().map { it.toString() },
            "conversion must not change which key the challenge asks for"
        )
    }

    @Test
    fun `test widevine pssh key id matches the manifest default KID`() {
        val manifest = "playlist/bitmovin.mpd"
        val pssh = psshFrom(manifest, "cenc:pssh")

        assertEquals(listOf(defaultKidOf(manifest)), pssh.keyIds().map { it.toString() })
    }
}
