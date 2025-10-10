package org.samfun.ktvine

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import kotlinx.coroutines.runBlocking
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.crypto.crypto
import org.samfun.ktvine.crypto.rsaPssSignSha1
import org.samfun.ktvine.crypto.rsaPssVerifySha1
import org.samfun.ktvine.proto.LicenseType
import org.samfun.ktvine.utils.kidToUuid
import org.samfun.ktvine.utils.toHexString
import java.net.HttpURLConnection
import java.net.URI
import java.nio.file.Files
import java.nio.file.Paths
import java.security.SecureRandom
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

@OptIn(DelicateCryptographyApi::class)
class CDMJvmTest {

    private fun readTestFile(name: String): ByteArray {
        // Try module-relative path first (when working dir is library/)
        val modulePath = Paths.get(
            "src", "commonTest", "kotlin", "org", "samfun", "ktvine", "device", name
        )
        if (Files.exists(modulePath)) return Files.readAllBytes(modulePath)

        // Fallback to repo-root-relative path
        val rootPath = Paths.get(
            "library", "src", "commonTest", "kotlin", "org", "samfun", "ktvine", "device", name
        )
        return Files.readAllBytes(rootPath)
    }

    private fun readMpd(): String {
        // Relative to module directory
        val path = Paths.get("src", "commonTest", "kotlin", "org", "samfun", "ktvine", "playlist", "tears.mpd")
        return Files.readString(path)
    }

    private fun extractFirstPsshB64(mpdXml: String): String? {
        val regex = Regex("<cenc:pssh\\b[^>]*>([^<]+)</cenc:pssh>")
        return regex.find(mpdXml)?.groupValues?.getOrNull(1)?.trim()
    }

    @Test
    fun sign_with_rsa_pss_sha1() {
        runBlocking {
            val rsa = crypto.get(RSA.PSS)
            val keyPair = rsa.keyPairGenerator(2048.bits, SHA1).generateKey()
            val private = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.DER.PKCS1)
            val public = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.DER)

            val data = ByteArray(32) { SecureRandom().nextInt(0, 256).toByte() }
            val signature = rsaPssSignSha1(private, data)
            val verified = rsaPssVerifySha1(public, data, signature)
            assertTrue(verified, "Signature verification failed")
        }
    }

    @Test
    fun widevine_proxy_returns_keys_when_device_available() {
        runBlocking {
            val data = try {
                readTestFile("google_avd.wvd")
            } catch (_: Throwable) {
                return@runBlocking
            }

            val device = Device.loads(data)
            val cdm = Cdm.fromDevice(device)
            val sessionId = cdm.open()

            val mpd = readMpd()
            val psshB64 = requireNotNull(extractFirstPsshB64(mpd)) { "No cenc:pssh found in MPD" }

            val pssh = PSSH(psshB64)

            val challenge = cdm.getLicenseChallenge(sessionId, pssh, LicenseType.STREAMING, privacyMode = false)

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

//            MDAwMDAwMDAwMDAwMDAwMQ== 	eKHcBkYRlwfpA1FNigBzXw== 	SD
//            MDAwMDAwMDAwMDAwMDAwMw== 	QkZshCrBxUObHgwJ+7Th0g== 	HD
//            MDAwMDAwMDAwMDAwMDAwMg== 	Hzeeo4xw5Af3ayPsZAHK7w== 	HD
//            MDAwMDAwMDAwMDAwMDAwMA== 	Pwoz80CYueIrwHjgobXoVA== 	AUDIO
//            MDAwMDAwMDAwMDAwMDAwNA== 	IvCfhLVopdAH5LHRFpQ1gQ== 	SD
//            MDAwMDAwMDAwMDAwMDAwNQ== 	msMDbgSsnSvpRu1iQFFJvA== 	SD
//            MDAwMDAwMDAwMDAwMDAwNg== 	MUWYWCQzTsTLSsS9w+K+7w== 	SD
//            MDAwMDAwMDAwMDAwMDAwNw== 	ebhzT7mNJ1qQempaFQEouw== 	HD

            // From https://integration.widevine.com/documentation/content
            val kids = listOf(
                Triple(
                    Base64.decode("MDAwMDAwMDAwMDAwMDAwMQ==").toByteString().kidToUuid(),
                    Base64.decode("eKHcBkYRlwfpA1FNigBzXw==").toHexString(),
                    "SD"
                ),
                Triple(
                    Base64.decode("MDAwMDAwMDAwMDAwMDAwMw==").toByteString().kidToUuid(),
                    Base64.decode("QkZshCrBxUObHgwJ+7Th0g==").toHexString(),
                    "HD"
                ),
                Triple(
                    Base64.decode("MDAwMDAwMDAwMDAwMDAwMg==").toByteString().kidToUuid(),
                    Base64.decode("Hzeeo4xw5Af3ayPsZAHK7w==").toHexString(),
                    "HD"
                ),
                Triple(
                    Base64.decode("MDAwMDAwMDAwMDAwMDAwMA==").toByteString().kidToUuid(),
                    Base64.decode("Pwoz80CYueIrwHjgobXoVA==").toHexString(),
                    "AUDIO"
                ),
                Triple(
                    Base64.decode("MDAwMDAwMDAwMDAwMDAwNA==").toByteString().kidToUuid(),
                    Base64.decode("IvCfhLVopdAH5LHRFpQ1gQ==").toHexString(),
                    "SD"
                ),
                Triple(
                    Base64.decode("MDAwMDAwMDAwMDAwMDAwNQ==").toByteString().kidToUuid(),
                    Base64.decode("msMDbgSsnSvpRu1iQFFJvA==").toHexString(),
                    "SD"
                ),
                Triple(
                    Base64.decode("MDAwMDAwMDAwMDAwMDAwNg==").toByteString().kidToUuid(),
                    Base64.decode("MUWYWCQzTsTLSsS9w+K+7w==").toHexString(),
                    "SD"
                ),
                Triple(
                    Base64.decode("MDAwMDAwMDAwMDAwMDAwNw==").toByteString().kidToUuid(),
                    Base64.decode("ebhzT7mNJ1qQempaFQEouw==").toHexString(),
                    "HD"
                ),
            )


            kids.forEach { (kid, expectedKeyHex, quality) ->
                println("Verifying KID $kid - $quality")
                val key = keys.find { it.kid == kid }
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
