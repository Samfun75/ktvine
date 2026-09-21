package org.samfun.ktprd.serve

import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktprd.remote.RemotePlayreadyCdm
import org.samfun.ktprd.remote.RemotePlayreadyCdmException
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.DeviceMismatchException
import org.samfun.ktvine.utils.toUUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * The serve wire contract, and ktprd's own client driving it end to end.
 *
 * Cross-testing the two halves is what catches an encoding the server writes and the client
 * cannot read; the Widevine side found two real defects that way which its mocks could not.
 */
class ServeRoutingTest {

    private val secret = "test-secret"
    private val deviceName = "test_device"
    private val kid = Uuid.parse("11223344-5566-7788-99aa-bbccddeeff00")

    private val json = Json { ignoreUnknownKeys = true }

    private fun header(): String =
        PlayreadyHeader.build(keyIds = listOf(kid), algid = "AESCTR", laUrl = "https://ls.example.com/rights")

    private fun config(): PlayreadyServeConfig = PlayreadyServeConfig(
        devices = mapOf(deviceName to ServeTestDevice.get()),
        users = mapOf(secret to PlayreadyServeUser("tester", setOf(deviceName))),
    )

    private fun ApplicationTestBuilder.install(config: PlayreadyServeConfig) {
        application { routing { ktprdCdm(config) } }
    }

    @Test
    fun `test the root announces itself as a playready serve API`() = testApplication {
        install(config())

        val response = client.get("/")
        assertEquals(HttpStatusCode.OK, response.status)
        assertTrue(response.headers["Server"]!!.contains("playready serve"))
        assertEquals("OK", json.parseToJsonElement(response.bodyAsText()).jsonObject["message"]!!.jsonPrimitive.content)
    }

    @Test
    fun `test an unauthenticated call is refused`() = testApplication {
        install(config())

        assertEquals(HttpStatusCode.Unauthorized, client.get("/$deviceName/open").status)
    }

    @Test
    fun `test a device the user may not use is refused without naming it`() = testApplication {
        install(config())

        val response = client.get("/another_device/open") { header("X-Secret-Key", secret) }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue(response.bodyAsText().contains("is not found or you may not use it"))
    }

    @Test
    fun `test open reports the device security level`() = testApplication {
        install(config())

        val response = client.get("/$deviceName/open") { header("X-Secret-Key", secret) }
        assertEquals(HttpStatusCode.OK, response.status)

        val data = json.parseToJsonElement(response.bodyAsText()).jsonObject["data"]!!.jsonObject
        assertEquals(32, data["session_id"]!!.jsonPrimitive.content.length, "a session id is 16 bytes of hex")
        assertEquals(
            "3000",
            data["device"]!!.jsonObject["security_level"]!!.jsonPrimitive.content,
        )
    }

    @Test
    fun `test a malformed session id is refused`() = testApplication {
        install(config())

        val response = client.post("/$deviceName/get_keys") {
            header("X-Secret-Key", secret)
            contentType(ContentType.Application.Json)
            setBody("""{"session_id":"not-hex"}""")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `test a body that is not a JSON object is refused`() = testApplication {
        install(config())

        val response = client.post("/$deviceName/parse_license") {
            header("X-Secret-Key", secret)
            contentType(ContentType.Application.Json)
            setBody("[]")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `test ktprd's own client can open, challenge and close against this server`() = testApplication {
        install(config())

        val cdm = RemotePlayreadyCdm(
            client = createClient { },
            baseUrl = "",
            deviceName = deviceName,
            secret = secret,
            expectedSecurityLevel = 3000,
        )

        cdm.probe()

        val sessionId = cdm.open()
        assertEquals(3000, cdm.securityLevel)

        val challenge = cdm.getLicenseChallenge(sessionId, WrmHeader.parse(header()))
        assertTrue(challenge.startsWith("<?xml version=\"1.0\" encoding=\"utf-8\"?><soap:Envelope"))
        assertTrue(challenge.contains("<ContentHeader>${header()}</ContentHeader>"))

        assertEquals(emptyList(), cdm.getKeys(sessionId))

        cdm.close(sessionId)
    }

    @Test
    fun `test a challenge may be requested with a Base64 PSSH instead of a header`() = testApplication {
        install(config())

        val pssh = PSSH.new(systemId = PSSH.PLAYREADY_SYSTEM_ID.toUUID(), keyIds = listOf(kid)).exportBase64()

        val open = client.get("/$deviceName/open") { header("X-Secret-Key", secret) }
        val sessionId = json.parseToJsonElement(open.bodyAsText())
            .jsonObject["data"]!!.jsonObject["session_id"]!!.jsonPrimitive.content

        val response = client.post("/$deviceName/get_license_challenge") {
            header("X-Secret-Key", secret)
            contentType(ContentType.Application.Json)
            setBody("""{"session_id":"$sessionId","init_data":"$pssh"}""")
        }

        assertEquals(HttpStatusCode.OK, response.status)
        val challenge = json.parseToJsonElement(response.bodyAsText())
            .jsonObject["data"]!!.jsonObject["challenge"]!!.jsonPrimitive.content
        assertTrue(challenge.contains("<WRMHEADER"))
    }

    @Test
    fun `test the client surfaces a server rejection as a typed error`() = testApplication {
        install(config())

        val cdm = RemotePlayreadyCdm(
            client = createClient { },
            baseUrl = "",
            deviceName = "another_device",
            secret = secret,
        )

        val error = assertFailsWith<RemotePlayreadyCdmException> { cdm.open() }
        assertEquals(403, error.status)
        assertTrue(error.serverMessage.contains("is not found or you may not use it"))
    }

    @Test
    fun `test the client rejects a device whose security level differs`() = testApplication {
        install(config())

        val cdm = RemotePlayreadyCdm(
            client = createClient { },
            baseUrl = "",
            deviceName = deviceName,
            secret = secret,
            expectedSecurityLevel = 2000,
        )

        assertFailsWith<DeviceMismatchException> { cdm.open() }
    }

    @Test
    fun `test parsing an empty license is refused`() = testApplication {
        install(config())

        val open = client.get("/$deviceName/open") { header("X-Secret-Key", secret) }
        val sessionId = json.parseToJsonElement(open.bodyAsText())
            .jsonObject["data"]!!.jsonObject["session_id"]!!.jsonPrimitive.content

        val response = client.post("/$deviceName/parse_license") {
            header("X-Secret-Key", secret)
            contentType(ContentType.Application.Json)
            setBody("""{"session_id":"$sessionId","license_message":""}""")
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }
}
