package org.samfun.ktprd

import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.cdm.PlayreadyCdm
import org.samfun.ktprd.core.PlayreadyDevice
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktprd.revocation.RevocationList
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.utils.toHexString
import java.net.HttpURLConnection
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * A real license exchange against Microsoft's public PlayReady test server.
 *
 * **This test needs the network and a real `.prd`.** It is excluded from `jvmTest` and runs only
 * under `./gradlew :ktprd:integrationTest`, mirroring how the Widevine side treats its live
 * proxy test.
 *
 * Nothing offline can establish that the challenge is byte-exact enough for a real server to
 * accept: the offline exchange checks the digest and signature against ktprd's own reading of the
 * document, and a server that disagreed about the framing would still reject it. This is the only
 * test that closes that gap.
 */
class PlayreadyProxyIntegrationTest {

    // `cfg=` configures Microsoft's test harness, not PlayReady; it rejects a `ckt:` key now.
    private val server = System.getenv("KTPRD_LICENSE_SERVER")
        ?: "https://test.playready.microsoft.com/service/rightsmanager.asmx?cfg=(persist:false,sl:2000)"

    private val devicePaths = listOf(
        "device/playready/Changhong-CBU-6510-PlayReady-SL3000/" +
            "sichuan_changhong_electric_co_ltd_stb_cbu-6510_sl3000.prd",
        "device/playready/Haier-ATV-hanyang-PlayReady-SL3000/" +
            "qingdao_haier_optronics_coltd_haier_atv_hanyang_sl3000_13cb583c.prd",
        "device/playready/LG-W23A-Playready-SL3000/lg_electronics_inc_lg_webos_tv_w23a_sl3000_9c34a494.prd",
        "device/playready/lg_webos_tv_sl3000/lg_electronics_inc_lg_webos_tv_msd96alvx_sl3000_30b7497d.prd",
    )

    /** The fault a server returns for a device Microsoft has revoked. */
    private val revokedStatusCode = "0x8004c065"

    /** Microsoft's published test content header, which its test server issues keys for. */
    private val testPssh =
        "AAADfHBzc2gAAAAAmgTweZhAQoarkuZb4IhflQAAA1xcAwAAAQABAFIDPABXAFIATQBIAEUAQQBEAEUAUgAgAHgAbQBsAG4AcwA9ACIAaAB0" +
            "AHQAcAA6AC8ALwBzAGMAaABlAG0AYQBzAC4AbQBpAGMAcgBvAHMAbwBmAHQALgBjAG8AbQAvAEQAUgBNAC8AMgAwADAANwAvADAAMwAv" +
            "AFAAbABhAHkAUgBlAGEAZAB5AEgAZQBhAGQAZQByACIAIAB2AGUAcgBzAGkAbwBuAD0AIgA0AC4AMAAuADAALgAwACIAPgA8AEQAQQBU" +
            "AEEAPgA8AFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBFAFkATABFAE4APgAxADYAPAAvAEsARQBZAEwARQBOAD4APABBAEwARwBJ" +
            "AEQAPgBBAEUAUwBDAFQAUgA8AC8AQQBMAEcASQBEAD4APAAvAFAAUgBPAFQARQBDAFQASQBOAEYATwA+ADwASwBJAEQAPgA0AFIAcABs" +
            "AGIAKwBUAGIATgBFAFMAOAB0AEcAawBOAEYAVwBUAEUASABBAD0APQA8AC8ASwBJAEQAPgA8AEMASABFAEMASwBTAFUATQA+AEsATABq" +
            "ADMAUQB6AFEAUAAvAE4AQQA9ADwALwBDAEgARQBDAEsAUwBVAE0APgA8AEwAQQBfAFUAUgBMAD4AaAB0AHQAcABzADoALwAvAHAAcgBv" +
            "AGYAZgBpAGMAaQBhAGwAcwBpAHQAZQAuAGsAZQB5AGQAZQBsAGkAdgBlAHIAeQAuAG0AZQBkAGkAYQBzAGUAcgB2AGkAYwBlAHMALgB3" +
            "AGkAbgBkAG8AdwBzAC4AbgBlAHQALwBQAGwAYQB5AFIAZQBhAGQAeQAvADwALwBMAEEAXwBVAFIATAA+ADwAQwBVAFMAVABPAE0AQQBU" +
            "AFQAUgBJAEIAVQBUAEUAUwA+ADwASQBJAFMAXwBEAFIATQBfAFYARQBSAFMASQBPAE4APgA4AC4AMQAuADIAMwAwADQALgAzADEAPAAv" +
            "AEkASQBTAF8ARABSAE0AXwBWAEUAUgBTAEkATwBOAD4APAAvAEMAVQBTAFQATwBNAEEAVABUAFIASQBCAFUAVABFAFMAPgA8AC8ARABB" +
            "AFQAQQA+ADwALwBXAFIATQBIAEUAQQBEAEUAUgA+AA=="

    private fun post(body: String): Pair<Int, String> {
        val connection = URI(server).toURL().openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.doOutput = true
        connection.connectTimeout = 30_000
        connection.readTimeout = 30_000
        connection.setRequestProperty("Content-Type", "text/xml; charset=UTF-8")

        connection.outputStream.use { it.write(body.encodeToByteArray()) }

        val status = connection.responseCode
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.bufferedReader()?.use { it.readText() }.orEmpty()
        connection.disconnect()
        return status to text
    }

    @Test
    fun `test a real exchange with the Microsoft test server yields a content key`() = runTest {
        val header = WrmHeader.from(PSSH(testPssh)).first()
        println("content header version ${header.version}, key ids ${header.keyIds.map { it.value }}")

        var attempted = 0
        var revoked = 0

        for (path in devicePaths) {
            val deviceBytes = TestFixtures.orSkip(path) ?: continue
            attempted++

            val device = PlayreadyDevice.loads(deviceBytes)
            val cdm = PlayreadyCdm.fromDevice(device)
            val sessionId = cdm.open()
            val challenge = cdm.getLicenseChallenge(sessionId, header, RevocationList.SUPPORTED_LIST_IDS)

            val (status, response) = post(challenge)
            println("${device.name}: HTTP $status")

            if (status != 200) {
                // A revocation fault still means the server parsed the challenge, checked its
                // signature and read the certificate chain out of it — the format is accepted and
                // the device is not. Anything else is ktprd's problem.
                assertTrue(
                    response.contains(revokedStatusCode, ignoreCase = true),
                    "${device.name} was rejected for something other than revocation: ${response.take(600)}",
                )
                println("  device is revoked by Microsoft; the challenge itself was accepted")
                revoked++
                cdm.close(sessionId)
                continue
            }

            cdm.parseLicense(sessionId, response)
            val keys = cdm.getKeys(sessionId)

            assertTrue(keys.isNotEmpty(), "the server returned a license with no content key")
            keys.forEach { println("  ${it.kid}:${it.key.toHexString()} (${it.keyType})") }

            // The header advertises a checksum for its key id; a key that passes it is the right
            // key, not merely a key the license happened to decrypt to.
            keys.forEach { key ->
                assertTrue(header.verifyChecksum(key.kid, key.key), "content key for ${key.kid} failed its checksum")
            }

            cdm.close(sessionId)
            return@runTest
        }

        if (attempted == 0) {
            println("SKIP: no PlayReady device fixtures are present, so no live exchange was attempted")
            return@runTest
        }

        assertEquals(
            attempted,
            revoked,
            "no device produced a license and not all of them were revoked",
        )
        println(
            "SKIP: all $attempted device(s) are revoked by Microsoft. The server accepted and " +
                "validated every challenge, so the wire format is confirmed; supply an unrevoked " +
                "device to also confirm key extraction against a live server.",
        )
    }
}
