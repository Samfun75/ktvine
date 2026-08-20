package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.SignedMessage
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RequestIdJvmTest {

    private fun requestIdOf(challenge: ByteArray): ByteArray {
        val signed = SignedMessage.ADAPTER.decode(challenge)
        val request = LicenseRequest.ADAPTER.decode(signed.msg!!)
        return request.content_id!!.widevine_pssh_data!!.request_id!!.toByteArray()
    }

    private suspend fun challengeFrom(device: Device): ByteArray {
        val cdm = Cdm.fromDevice(device)
        val sessionId = cdm.open()
        val pssh = PSSH(
            TestFixtures.readText("playlist/tears.mpd").let { xml ->
                Regex("""<cenc:pssh\b[^>]*>([^<]+)</cenc:pssh>""").find(xml)!!.groupValues[1].trim()
            },
        )
        return cdm.getLicenseChallenge(sessionId, pssh)
    }

    @Test
    fun `test android devices emit a 32 byte uppercase hex request id`() {
        runBlocking {
            val data = TestFixtures.orSkip("device/google_avd.wvd") ?: return@runBlocking
            val device = Device.loads(data)
            assertEquals(DeviceTypes.ANDROID, device.type, "fixture is expected to be an Android device")

            val requestId = requestIdOf(challengeFrom(device))

            // Real OEMCrypto example: A0DCE548000000000500000000000000
            assertEquals(32, requestId.size, "Android request ids are 32 ASCII bytes, not 16 raw ones")
            val text = requestId.decodeToString()
            assertTrue(
                Regex("^[0-9A-F]{32}$").matches(text),
                "expected uppercase hex, got $text",
            )
            // Bytes 5-8 of the underlying block are zero, and the counter is little-endian.
            assertEquals("00000000", text.substring(8, 16), "bytes 5-8 should be zero: $text")
            assertEquals("0100000000000000", text.substring(16), "session 1 counter, little-endian: $text")
        }
    }

    @Test
    fun `test request ids differ between sessions`() {
        runBlocking {
            val data = TestFixtures.orSkip("device/google_avd.wvd") ?: return@runBlocking
            val device = Device.loads(data)

            val first = requestIdOf(challengeFrom(device)).decodeToString()
            val second = requestIdOf(challengeFrom(device)).decodeToString()

            assertTrue(first != second, "two challenges produced the same request id")
        }
    }
}
