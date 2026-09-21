package org.samfun.ktvine.serve

import io.ktor.client.request.get
import io.ktor.client.request.head
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.http.contentType
import io.ktor.server.routing.routing
import io.ktor.server.testing.ApplicationTestBuilder
import io.ktor.server.testing.testApplication
import kotlinx.coroutines.test.runTest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.remote.RemoteCdm
import org.samfun.ktvine.utils.DeviceMismatchException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

private const val SECRET = "aTestSecretKeyThatIsNotReal00000"
private const val DEVICE_NAME = "test_device"

/**
 * The wire contract, checked from the outside.
 *
 * These assert the shapes pywidevine's own client reads, so they fail if the envelope or a
 * field name drifts — the same drift a live cross-test would catch, but hermetically.
 */
class ServeRoutingTest {

    private val json = Json { ignoreUnknownKeys = true }

    private fun ApplicationTestBuilder.mount(device: Device, forcePrivacyMode: Boolean = false) {
        application {
            routing {
                ktvineCdm(
                    ServeConfig(
                        devices = mapOf(DEVICE_NAME to device),
                        users = mapOf(SECRET to ServeUser("tester", setOf(DEVICE_NAME))),
                        forcePrivacyMode = forcePrivacyMode,
                    ),
                )
            }
        }
    }

    @Test
    fun `test ping answers without a secret key`() = testApplication {
        mount(TestDevice.make())
        val body = client.get("/").bodyAsText()
        assertEquals(200, json.parseToJsonElement(body).jsonObject["status"]?.jsonPrimitive?.content?.toInt())
    }

    @Test
    fun `test the head probe pywidevine's client makes is answered`() = testApplication {
        mount(TestDevice.make())

        val response = client.head("/")
        assertEquals(HttpStatusCode.OK, response.status)

        // pywidevine refuses any server whose Server header it cannot version-match.
        val server = response.headers[HttpHeaders.Server]
        assertNotNull(server, "a Server header is required by pywidevine's client")
        assertTrue("pywidevine serve" in server.lowercase(), server)
        val version = Regex("""pywidevine serve v([\d.]+)""", RegexOption.IGNORE_CASE).find(server)
        assertNotNull(version, "the version must be greppable out of: $server")
        assertTrue(version.groupValues[1] >= "1.4.3", "advertised ${version.groupValues[1]}")
    }

    @Test
    fun `test a missing secret key is rejected`() = testApplication {
        mount(TestDevice.make())
        val response = client.get("/$DEVICE_NAME/open")
        assertEquals(HttpStatusCode.Unauthorized, response.status)
    }

    @Test
    fun `test an unauthorised device is not distinguished from a missing one`() = testApplication {
        mount(TestDevice.make())
        val response = client.get("/no_such_device/open") { header("X-Secret-Key", SECRET) }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue("not found or you may not use it" in response.bodyAsText())
    }

    @Test
    fun `test open returns the envelope pywidevine's client reads`() = testApplication {
        val device = TestDevice.make()
        mount(device)

        val body = client.get("/$DEVICE_NAME/open") { header("X-Secret-Key", SECRET) }.bodyAsText()
        val envelope = json.parseToJsonElement(body).jsonObject

        assertEquals(200, envelope["status"]?.jsonPrimitive?.content?.toInt())
        val data = envelope["data"]!!.jsonObject
        val sessionId = data["session_id"]!!.jsonPrimitive.content
        assertEquals(32, sessionId.length, "session_id is a 16-byte hex string")
        assertEquals(device.systemId, data["device"]!!.jsonObject["system_id"]!!.jsonPrimitive.content.toInt())
        assertEquals(
            device.securityLevel,
            data["device"]!!.jsonObject["security_level"]!!.jsonPrimitive.content.toInt(),
        )
    }

    @Test
    fun `test an unknown session is refused`() = testApplication {
        mount(TestDevice.make())
        // Open first so a Cdm exists for this user and device.
        client.get("/$DEVICE_NAME/open") { header("X-Secret-Key", SECRET) }

        val response = client.get("/$DEVICE_NAME/close/${"00".repeat(16)}") {
            header("X-Secret-Key", SECRET)
        }
        assertEquals(HttpStatusCode.BadRequest, response.status)
    }

    @Test
    fun `test forced privacy mode refuses a bare challenge`() = testApplication {
        mount(TestDevice.make(), forcePrivacyMode = true)

        val open = client.get("/$DEVICE_NAME/open") { header("X-Secret-Key", SECRET) }.bodyAsText()
        val sessionId = json.parseToJsonElement(open).jsonObject["data"]!!
            .jsonObject["session_id"]!!.jsonPrimitive.content

        val response = client.post("/$DEVICE_NAME/get_license_challenge/STREAMING") {
            header("X-Secret-Key", SECRET)
            contentType(ContentType.Application.Json)
            setBody(
                """{"session_id":"$sessionId","init_data":"${TestDevice.PSSH_B64}","privacy_mode":false}""",
            )
        }
        assertEquals(HttpStatusCode.Forbidden, response.status)
        assertTrue("Privacy Mode is Enforced" in response.bodyAsText())
    }

    @Test
    fun `test ktvine's own RemoteCdm drives this server`() = testApplication {
        val device = TestDevice.make()
        mount(device)

        val cdm = RemoteCdm(client, "", DEVICE_NAME, SECRET, device.systemId, device.securityLevel)

        val session = cdm.open()
        assertEquals(device.systemId, cdm.systemId)
        assertEquals(device.securityLevel, cdm.securityLevel)

        val challenge = cdm.getLicenseChallenge(session, TestDevice.pssh(), privacyMode = false)
        assertTrue(challenge.isNotEmpty(), "the server should return a signed challenge")

        assertTrue(cdm.getKeys(session).isEmpty(), "no licence parsed yet")
        cdm.close(session)
    }

    @Test
    fun `test RemoteCdm rejects this server when the device does not match`() = testApplication {
        val device = TestDevice.make()
        mount(device)

        val cdm = RemoteCdm(client, "", DEVICE_NAME, SECRET, expectedSystemId = device.systemId + 1)
        assertFailsWith<DeviceMismatchException> { cdm.open() }
    }

    @Test
    fun `test the service certificate round trips through the server`() = testApplication {
        val device = TestDevice.make()
        mount(device)

        val cdm = RemoteCdm(client, "", DEVICE_NAME, SECRET)
        val session = cdm.open()

        val provider = cdm.setServiceCertificate(session, org.samfun.ktvine.cdm.Cdm.COMMON_PRIVACY_CERT)
        assertEquals("license.widevine.com", provider)
        assertNotNull(cdm.getServiceCertificateBase64(session))

        cdm.setServiceCertificate(session, null)
        assertEquals(null, cdm.getServiceCertificateBase64(session))
        cdm.close(session)
    }

    @Test
    fun `test the session cap is reported through the envelope`() = runTest {
        testApplication {
            mount(TestDevice.make())
            val cdm = RemoteCdm(client, "", DEVICE_NAME, SECRET)
            repeat(org.samfun.ktvine.cdm.Cdm.MAX_NUM_OF_SESSIONS) { cdm.open() }

            val failure = assertFailsWith<org.samfun.ktvine.remote.RemoteCdmException> { cdm.open() }
            assertEquals(400, failure.status)
            assertTrue("Too many Sessions" in failure.serverMessage, failure.serverMessage)
        }
    }
}
