@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd.remote

import io.ktor.client.HttpClient
import io.ktor.client.engine.mock.MockEngine
import io.ktor.client.engine.mock.respond
import io.ktor.client.request.HttpRequestData
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.headersOf
import io.ktor.utils.io.ByteReadChannel
import kotlinx.coroutines.test.runTest
import okio.ByteString.Companion.decodeHex
import org.samfun.ktprd.core.PlayreadyCipherType
import org.samfun.ktprd.core.PlayreadyKeyType
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.utils.DeviceMismatchException
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** The wire format `RemotePlayreadyCdm` speaks, pinned against a mock server. */
class RemotePlayreadyCdmTest {

    private val secret = "s3cret"
    private val sessionHex = "000102030405060708090a0b0c0d0e0f"
    private val kid = Uuid.parse("11223344-5566-7788-99aa-bbccddeeff00")

    private val recorded = mutableListOf<HttpRequestData>()

    private fun cdm(
        expectedSecurityLevel: Int? = null,
        handler: (HttpRequestData) -> Pair<HttpStatusCode, String>,
    ): RemotePlayreadyCdm {
        val engine = MockEngine { request ->
            recorded += request
            val (status, body) = handler(request)
            respond(
                content = ByteReadChannel(body),
                status = status,
                headers = headersOf(
                    HttpHeaders.ContentType to listOf("application/json"),
                    HttpHeaders.Server to listOf("ktprd-serve (pyplayready serve v0.8.1 compatible)"),
                ),
            )
        }
        return RemotePlayreadyCdm(
            client = HttpClient(engine),
            baseUrl = "https://cdm.example.com/",
            deviceName = "my_device",
            secret = secret,
            expectedSecurityLevel = expectedSecurityLevel,
        )
    }

    private fun header(): WrmHeader = WrmHeader.parse(PlayreadyHeader.build(listOf(kid), "AESCTR"))

    private val openBody =
        """{"message":"Success","data":{"session_id":"$sessionHex","device":{"security_level":3000}}}"""

    @Test
    fun `test open sends the secret and reads the session and security level`() = runTest {
        val cdm = cdm { HttpStatusCode.OK to openBody }

        val sessionId = cdm.open()

        assertEquals(sessionHex, sessionId.hex())
        assertEquals(3000, cdm.securityLevel)
        assertEquals("https://cdm.example.com/my_device/open", recorded.single().url.toString())
        assertEquals(secret, recorded.single().headers["X-Secret-Key"])
    }

    @Test
    fun `test a trailing slash on the base url does not double up`() = runTest {
        cdm { HttpStatusCode.OK to openBody }.open()
        assertTrue(!recorded.single().url.toString().contains("//my_device"))
    }

    @Test
    fun `test a security level that differs from the expectation is refused`() = runTest {
        val cdm = cdm(expectedSecurityLevel = 2000) { HttpStatusCode.OK to openBody }
        assertFailsWith<DeviceMismatchException> { cdm.open() }
    }

    @Test
    fun `test close addresses the session by hex`() = runTest {
        val cdm = cdm { HttpStatusCode.OK to """{"message":"Successfully closed"}""" }
        cdm.close(sessionHex.decodeHex())

        assertEquals("https://cdm.example.com/my_device/close/$sessionHex", recorded.single().url.toString())
    }

    @Test
    fun `test the challenge request carries the header and revocation lists`() = runTest {
        var body = ""
        val cdm = cdm { request ->
            body = (request.body as io.ktor.http.content.TextContent).text
            HttpStatusCode.OK to """{"message":"Success","data":{"challenge":"<soap:Envelope/>"}}"""
        }

        val lists = listOf(Uuid.parse("52d1ff11-d388-4edd-82b7-68ea4c20a16c"))
        val challenge = cdm.getLicenseChallenge(sessionHex.decodeHex(), header(), lists)

        assertEquals("<soap:Envelope/>", challenge)
        assertTrue(body.contains("\"session_id\":\"$sessionHex\""))
        assertTrue(body.contains("WRMHEADER"), "the header must go out as init_data")
        assertTrue(body.contains("52d1ff11-d388-4edd-82b7-68ea4c20a16c"))
    }

    @Test
    fun `test no revocation lists means the field is omitted entirely`() = runTest {
        var body = ""
        val cdm = cdm { request ->
            body = (request.body as io.ktor.http.content.TextContent).text
            HttpStatusCode.OK to """{"message":"Success","data":{"challenge":"x"}}"""
        }

        cdm.getLicenseChallenge(sessionHex.decodeHex(), header())
        assertTrue(!body.contains("rev_lists"))
    }

    @Test
    fun `test keys come back decoded from hex`() = runTest {
        val keyHex = "000102030405060708090a0b0c0d0e0f"
        val kidHex = "44332211665588779" + "9aabbccddeeff00"
        val cdm = cdm {
            HttpStatusCode.OK to """{"message":"Success","data":{"keys":[
                {"key_id":"$kidHex","key":"$keyHex","type":1,"cipher_type":3,"key_length":16}
            ]}}"""
        }

        val keys = cdm.getKeys(sessionHex.decodeHex())

        assertEquals(1, keys.size)
        assertEquals(keyHex, keys[0].key.toHexString())
        assertEquals(PlayreadyKeyType.AES_128_CTR, keys[0].keyType)
        assertEquals(PlayreadyCipherType.ECC_256, keys[0].cipherType)
        assertEquals(16, keys[0].keyLength)
    }

    @Test
    fun `test an empty key list is not an error`() = runTest {
        val cdm = cdm { HttpStatusCode.OK to """{"message":"Success","data":{"keys":[]}}""" }
        assertEquals(emptyList(), cdm.getKeys(sessionHex.decodeHex()))
    }

    @Test
    fun `test a non success status becomes a typed error carrying the server message`() = runTest {
        val cdm = cdm { HttpStatusCode.Forbidden to """{"message":"Device 'x' is not found or you may not use it."}""" }

        val error = assertFailsWith<RemotePlayreadyCdmException> { cdm.open() }
        assertEquals(403, error.status)
        assertTrue(error.serverMessage.contains("not found"))
    }

    @Test
    fun `test a non JSON error body still produces a typed error`() = runTest {
        val cdm = cdm { HttpStatusCode.InternalServerError to "<html>gateway exploded</html>" }

        val error = assertFailsWith<RemotePlayreadyCdmException> { cdm.open() }
        assertEquals(500, error.status)
        assertTrue(error.serverMessage.contains("gateway exploded"))
    }

    @Test
    fun `test a JSON null field is not read as the text null`() = runTest {
        // A server sends an explicit null for a field it has no value for; decoding that as the
        // four characters "null" is a defect the Widevine client hit against a real server.
        val nullLevel =
            """{"message":"Success","data":{"session_id":"$sessionHex","device":{"security_level":null}}}"""
        val cdm = cdm { HttpStatusCode.OK to nullLevel }

        cdm.open()
        assertEquals(null, cdm.securityLevel)
    }

    @Test
    fun `test a missing session id is reported rather than assumed`() = runTest {
        val cdm = cdm { HttpStatusCode.OK to """{"message":"Success","data":{}}""" }
        assertFailsWith<DecodeException> { cdm.open() }
    }

    @Test
    fun `test a session id that is not hex is reported`() = runTest {
        val cdm = cdm { HttpStatusCode.OK to """{"message":"Success","data":{"session_id":"zzzz"}}""" }
        assertFailsWith<DecodeException> { cdm.open() }
    }

    @Test
    fun `test parse license posts the message verbatim`() = runTest {
        var body = ""
        val cdm = cdm { request ->
            body = (request.body as io.ktor.http.content.TextContent).text
            HttpStatusCode.OK to """{"message":"Successfully parsed"}"""
        }

        cdm.parseLicense(sessionHex.decodeHex(), "<soap:Envelope>license</soap:Envelope>")

        assertTrue(body.contains("license"))
        assertEquals("https://cdm.example.com/my_device/parse_license", recorded.single().url.toString())
    }
}
