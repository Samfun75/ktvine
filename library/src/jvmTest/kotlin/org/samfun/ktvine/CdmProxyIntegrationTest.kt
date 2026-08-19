package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.LicenseType
import org.samfun.ktvine.proto.SignedMessage
import org.samfun.ktvine.utils.toHexString
import java.net.HttpURLConnection
import java.net.URI
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Hits the live Widevine proxy. Excluded from `jvmTest`; run with `:library:integrationTest`.
 */
class CdmProxyIntegrationTest {

    private fun extractFirstPsshB64(mpdXml: String): String? {
        val regex = Regex("""<cenc:pssh\b[^>]*>([^<]+)</cenc:pssh>""")
        return regex.find(mpdXml)?.groupValues?.getOrNull(1)?.trim()
    }

    @Test
    fun `test widevine proxy returns keys when device available`() {
        runBlocking {
            val data = TestFixtures.orSkip("device/google_avd.wvd") ?: return@runBlocking

            val device = Device.loads(data)
            val cdm = Cdm.fromDevice(device)
            val sessionId = cdm.open()

            val mpd = TestFixtures.readText("playlist/tears.mpd")
            val psshB64 = requireNotNull(extractFirstPsshB64(mpd)) { "No cenc:pssh found in MPD" }

            val pssh = PSSH(psshB64)

            val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING)

            val url = URI.create("https://proxy.widevine.com/proxy").toURL()
            val conn = (url.openConnection() as HttpURLConnection).apply {
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/octet-stream")
                setRequestProperty("Accept", "application/octet-stream")
                connectTimeout = 15000
                readTimeout = 30000
            }

            conn.outputStream.use { it.write(challenge) }

            val response = conn.inputStream.use { it.readBytes() }

            // Parse license and assert we have at least one key
            cdm.parseLicense(sessionId, response)
            val keys = cdm.getKeys(sessionId)
            assertTrue(keys.isNotEmpty(), "No decryption keys returned by Widevine proxy")

            keys.forEach { key ->
                println("[${key.type}] ${key.kid} : ${key.key.toHexString()}")
            }

            // Published at https://integration.widevine.com/documentation/content.
            // These are literals on purpose: deriving them with kidToUuid would make the
            // test agree with whatever that function does, including being wrong.
            val kids = listOf(
                Triple("00000000-0000-0000-0000-000000000000", "3f0a33f34098b9e22bc078e0a1b5e854", "AUDIO"),
                Triple("00000000-0000-0000-0000-000000000001", "78a1dc0646119707e903514d8a00735f", "SD"),
                Triple("00000000-0000-0000-0000-000000000002", "1f379ea38c70e407f76b23ec6401caef", "HD"),
                Triple("00000000-0000-0000-0000-000000000003", "42466c842ac1c5439b1e0c09fbb4e1d2", "HD"),
                Triple("00000000-0000-0000-0000-000000000004", "22f09f84b568a5d007e4b1d116943581", "SD"),
                Triple("00000000-0000-0000-0000-000000000005", "9ac3036e04ac9d2be946ed62405149bc", "SD"),
                Triple("00000000-0000-0000-0000-000000000006", "3145985824334ec4cb4ac4bdc3e2beef", "SD"),
                Triple("00000000-0000-0000-0000-000000000007", "79b8734fb98d275a907a6a5a150128bb", "HD"),
            )

            // A renewal must reference the license just parsed, not the content.
            val renewalChallenge = cdm.getLicenseChallenge(
                sessionId,
                pssh,
                requestType = LicenseRequest.RequestType.RENEWAL
            )
            val renewal = LicenseRequest.ADAPTER.decode(
                SignedMessage.ADAPTER.decode(renewalChallenge).msg!!
            )
            assertEquals(LicenseRequest.RequestType.RENEWAL, renewal.type)
            assertTrue(
                renewal.content_id!!.widevine_pssh_data == null,
                "a renewal identifies the license, not the content"
            )
            assertEquals(
                cdm.getLicense(sessionId)!!.id,
                renewal.content_id!!.existing_license!!.license_id
            )

            // The parsed license itself must be reachable, not just its keys.
            val parsedLicense = cdm.getLicense(sessionId)
            assertTrue(parsedLicense != null, "parseLicense should retain the decoded License")
            assertTrue(parsedLicense.key.isNotEmpty(), "license should carry key containers")
            assertTrue(parsedLicense.policy != null, "license should carry a policy")
            println("License policy: ${parsedLicense.policy}")

            // Scoped to CONTENT: the license also carries a keyless SIGNING key, whose
            // absent KID legitimately maps to the nil UUID and would shadow KID ...0000.
            val contentKeys = cdm.getKeys(sessionId, License.KeyContainer.KeyType.CONTENT)

            kids.forEach { (kid, expectedKeyHex, quality) ->
                println("Verifying KID $kid - $quality")
                val key = contentKeys.find { it.kid.toString() == kid }
                assertTrue(key != null, "Key with KID $kid not found in license")
                assertEquals(
                    expectedKeyHex,
                    key.key.toHexString(),
                    "Key mismatch for KID $kid: expected $expectedKeyHex, got ${key.key.toHexString()}"
                )
            }
        }
    }
}
