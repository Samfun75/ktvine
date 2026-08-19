package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.SignedMessage
import org.samfun.ktvine.utils.InvalidContextException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class RequestTypeJvmTest {

    private fun pssh(): PSSH {
        val xml = TestFixtures.readText("playlist/tears.mpd")
        return PSSH(Regex("""<cenc:pssh\b[^>]*>([^<]+)</cenc:pssh>""").find(xml)!!.groupValues[1].trim())
    }

    private fun decodeRequest(challenge: ByteArray): LicenseRequest =
        LicenseRequest.ADAPTER.decode(SignedMessage.ADAPTER.decode(challenge).msg!!)

    @Test
    fun `test a new request carries the pssh and not an existing license`() {
        runBlocking {
            val data = TestFixtures.orSkip("device/google_avd.wvd") ?: return@runBlocking
            val cdm = Cdm.fromDevice(Device.loads(data))
            val sessionId = cdm.open()

            val request = decodeRequest(cdm.getLicenseChallenge(sessionId, pssh()))

            assertEquals(LicenseRequest.RequestType.NEW, request.type)
            assertNotNull(request.content_id!!.widevine_pssh_data)
            assertNull(request.content_id!!.existing_license)
        }
    }

    @Test
    fun `test renewal before a license is parsed reports missing context`() {
        runBlocking {
            val data = TestFixtures.orSkip("device/google_avd.wvd") ?: return@runBlocking
            val cdm = Cdm.fromDevice(Device.loads(data))
            val sessionId = cdm.open()

            assertFailsWith<InvalidContextException> {
                cdm.getLicenseChallenge(
                    sessionId,
                    pssh(),
                    requestType = LicenseRequest.RequestType.RENEWAL
                )
            }
            assertFailsWith<InvalidContextException> {
                cdm.getLicenseChallenge(
                    sessionId,
                    pssh(),
                    requestType = LicenseRequest.RequestType.RELEASE
                )
            }
        }
    }
}
