@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine.remote

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.engine.mock.toByteArray
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.test.runTest
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.LicenseType
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.utils.ValueException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Pins the wire format against pywidevine's `serve.py`.
 *
 * These use a mock transport, so they verify that ktvine speaks the protocol that source
 * documents — not that any particular deployed server accepts it.
 */
class RemoteCdmTest {

    private val sessionHex = "0102030405060708090a0b0c0d0e0f10"

    private class Recorder {
        val requests = mutableListOf<HttpRequestData>()
        val bodies = mutableListOf<String>()
    }

    private fun cdmFor(recorder: Recorder, respondWith: (String) -> String): RemoteCdm {
        val engine = MockEngine { request ->
            recorder.requests += request
            recorder.bodies += request.body.toByteArray().decodeToString()
            respond(
                content = ByteReadChannel(respondWith(request.url.encodedPath)),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }
        return RemoteCdm(HttpClient(engine), "https://cdm.example.com/", "test_device", "s3cret")
    }

    private fun ok(data: String) = """{"status":200,"message":"Success","data":$data}"""

    @Test
    fun `test open sends the secret header and reads the session and device`() = runTest {
        val recorder = Recorder()
        val cdm = cdmFor(recorder) {
            ok("""{"session_id":"$sessionHex","device":{"system_id":4464,"security_level":3}}""")
        }

        val sessionId = cdm.open()

        assertEquals(sessionHex.decodeHex(), sessionId)
        assertEquals(4464, cdm.systemId)
        assertEquals(3, cdm.securityLevel)

        val request = recorder.requests.single()
        assertEquals("/test_device/open", request.url.encodedPath)
        assertEquals("s3cret", request.headers["X-Secret-Key"], "the server authenticates on this header")
    }

    @Test
    fun `test close targets the session in the path`() = runTest {
        val recorder = Recorder()
        val cdm = cdmFor(recorder) { ok("null") }

        cdm.close(sessionHex.decodeHex())

        assertEquals("/test_device/close/$sessionHex", recorder.requests.single().url.encodedPath)
    }

    @Test
    fun `test the license challenge round trip matches serve dot py`() = runTest {
        val challenge = byteArrayOf(1, 2, 3, 4, 5)
        val recorder = Recorder()
        val cdm = cdmFor(recorder) { ok("""{"challenge_b64":"${challenge.toByteString().base64()}"}""") }

        val pssh = PSSH.new(
            systemId = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"),
            keyIds = listOf(Uuid.parse("11111111-2222-3333-4444-555555555555")),
            version = 1,
        )
        val result = cdm.getLicenseChallenge(sessionHex.decodeHex(), pssh, LicenseType.STREAMING, privacyMode = false)

        assertContentEquals(challenge, result)

        val request = recorder.requests.single()
        assertEquals("/test_device/get_license_challenge/STREAMING", request.url.encodedPath)

        val body = recorder.bodies.single()
        assertTrue("\"session_id\":\"$sessionHex\"" in body, body)
        assertTrue("\"init_data\":\"${pssh.exportBase64()}\"" in body, "init_data is the Base64 PSSH box: $body")
        assertTrue("\"privacy_mode\":false" in body, body)
    }

    @Test
    fun `test parse license posts the response as base64`() = runTest {
        val recorder = Recorder()
        val cdm = cdmFor(recorder) { ok("null") }
        val license = byteArrayOf(9, 8, 7)

        cdm.parseLicense(sessionHex.decodeHex(), license)

        assertEquals("/test_device/parse_license", recorder.requests.single().url.encodedPath)
        assertTrue("\"license_message\":\"${license.toByteString().base64()}\"" in recorder.bodies.single())
    }

    @Test
    fun `test keys are decoded from the hex the server returns`() = runTest {
        val recorder = Recorder()
        val cdm = cdmFor(recorder) {
            ok(
                """{"keys":[
                    {"key_id":"11111111222233334444555555555555",
                     "key":"000102030405060708090a0b0c0d0e0f",
                     "type":"CONTENT","permissions":[]},
                    {"key_id":"aaaaaaaabbbbccccddddeeeeeeeeeeee",
                     "key":"0f0e0d0c0b0a09080706050403020100",
                     "type":"OPERATOR_SESSION","permissions":["allow_decrypt"]}
                ]}""",
            )
        }

        val keys = cdm.getKeys(sessionHex.decodeHex())

        assertEquals(2, keys.size)
        assertEquals(Uuid.parse("11111111-2222-3333-4444-555555555555"), keys[0].kid)
        assertEquals(License.KeyContainer.KeyType.CONTENT, keys[0].type)
        assertContentEquals("000102030405060708090a0b0c0d0e0f".decodeHex().toByteArray(), keys[0].key)
        assertEquals(License.KeyContainer.KeyType.OPERATOR_SESSION, keys[1].type)
        assertEquals(listOf("allow_decrypt"), keys[1].permissions)

        assertEquals("/test_device/get_keys/ALL", recorder.requests.single().url.encodedPath)
    }

    @Test
    fun `test a key type filter is put in the path`() = runTest {
        val recorder = Recorder()
        val cdm = cdmFor(recorder) { ok("""{"keys":[]}""") }

        cdm.getKeys(sessionHex.decodeHex(), License.KeyContainer.KeyType.CONTENT)

        assertEquals("/test_device/get_keys/CONTENT", recorder.requests.single().url.encodedPath)
    }

    @Test
    fun `test setting and clearing the service certificate`() = runTest {
        val recorder = Recorder()
        val cdm = cdmFor(recorder) { ok("""{"provider_id":"license.widevine.com"}""") }

        assertEquals("license.widevine.com", cdm.setServiceCertificate(sessionHex.decodeHex(), "Q0VSVA=="))
        assertTrue("\"certificate\":\"Q0VSVA==\"" in recorder.bodies.last())

        cdm.setServiceCertificate(sessionHex.decodeHex(), null)
        assertTrue("\"certificate\":null" in recorder.bodies.last(), "clearing sends an explicit null")
    }

    @Test
    fun `test a server error becomes a typed exception`() = runTest {
        val engine = MockEngine {
            respond(
                content = ByteReadChannel(
                    """{"status":400,"message":"Invalid Session ID '00', it may have expired."}""",
                ),
                status = HttpStatusCode.BadRequest,
                headers = headersOf(HttpHeaders.ContentType, "application/json"),
            )
        }
        val cdm = RemoteCdm(HttpClient(engine), "https://cdm.example.com", "test_device", "s3cret")

        val failure = assertFailsWith<RemoteCdmException> { cdm.open() }
        assertEquals(400, failure.status)
        assertTrue("Invalid Session ID" in failure.serverMessage, failure.serverMessage)
    }

    @Test
    fun `test a non-envelope body is a decode error`() = runTest {
        val engine = MockEngine {
            respond(
                content = ByteReadChannel("<html>gateway timeout</html>"),
                status = HttpStatusCode.OK,
                headers = headersOf(HttpHeaders.ContentType, "text/html"),
            )
        }
        val cdm = RemoteCdm(HttpClient(engine), "https://cdm.example.com", "test_device", "s3cret")

        assertFailsWith<DecodeException> { cdm.open() }
    }

    @Test
    fun `test renewal is rejected because the protocol has no endpoint for it`() = runTest {
        val recorder = Recorder()
        val cdm = cdmFor(recorder) { ok("""{"challenge_b64":"AAA="}""") }
        val pssh = PSSH.new(
            systemId = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"),
            keyIds = listOf(Uuid.parse("11111111-2222-3333-4444-555555555555")),
            version = 1,
        )

        assertFailsWith<ValueException> {
            cdm.getLicenseChallenge(
                sessionHex.decodeHex(),
                pssh,
                LicenseType.STREAMING,
                privacyMode = true,
                requestType = LicenseRequest.RequestType.RENEWAL,
            )
        }
        assertTrue(recorder.requests.isEmpty(), "nothing should have been sent")
    }

    @Test
    fun `test a trailing slash in the base url does not double up`() = runTest {
        val recorder = Recorder()
        val cdm = cdmFor(recorder) { ok("""{"session_id":"$sessionHex"}""") }

        cdm.open()

        assertEquals("/test_device/open", recorder.requests.single().url.encodedPath)
    }
}
