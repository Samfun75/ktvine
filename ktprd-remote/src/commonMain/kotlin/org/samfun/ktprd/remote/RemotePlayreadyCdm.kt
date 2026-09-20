@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd.remote

import io.ktor.client.HttpClient
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.head
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.add
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import org.samfun.ktprd.cdm.PlayreadyCdmApi
import org.samfun.ktprd.core.PlayreadyCipherType
import org.samfun.ktprd.core.PlayreadyKey
import org.samfun.ktprd.core.PlayreadyKeyType
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktprd.utils.KtprdException
import org.samfun.ktprd.utils.KtprdLog
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.utils.DeviceMismatchException
import org.samfun.ktvine.utils.toUUID
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** A remote PlayReady CDM server rejected a request. [status] is the HTTP status it replied with. */
public class RemotePlayreadyCdmException(
    public val status: Int,
    public val serverMessage: String,
) : KtprdException("Remote PlayReady CDM returned $status: $serverMessage")

/**
 * A [PlayreadyCdmApi] backed by a `pyplayready serve`-compatible server.
 *
 * The device's private keys never reach this process — every operation is an HTTP call, so one
 * server can hold the devices while many clients use them.
 *
 * The caller supplies the [HttpClient], which keeps this module free of any engine choice:
 *
 * ```kotlin
 * val cdm = RemotePlayreadyCdm(
 *     client = HttpClient(CIO),
 *     baseUrl = "https://cdm.example.com",
 *     deviceName = "my_playready_device",
 *     secret = "your-api-key",
 * )
 * ```
 *
 * @param baseUrl the server root, with or without a trailing slash
 * @param deviceName the device the server should use, as named in its config
 * @param secret the value sent as the `X-Secret-Key` header
 * @param expectedSecurityLevel if given, [open] rejects a server whose device reports a different
 *   security level
 */
public class RemotePlayreadyCdm(
    private val client: HttpClient,
    baseUrl: String,
    private val deviceName: String,
    private val secret: String,
    private val expectedSecurityLevel: Int? = null,
) : PlayreadyCdmApi {

    private val root: String = baseUrl.trimEnd('/')
    private val json = Json { ignoreUnknownKeys = true }

    /** Security level the server reports for [deviceName]. Populated by the first [open]. */
    public var securityLevel: Int? = null
        private set

    /**
     * Check that [baseUrl] looks like a PlayReady CDM server.
     *
     * This only logs what it finds. A server that omits or renames the header is still perfectly
     * usable, and failing the whole client over a banner would be worse than being wrong about it.
     */
    public suspend fun probe() {
        val response = try {
            client.head(root) { authenticate() }
        } catch (e: Throwable) {
            KtprdLog.w { "Could not reach the remote PlayReady CDM to check its version, $e" }
            return
        }

        val server = response.headers["Server"]
        if (server == null || !server.contains("playready serve", ignoreCase = true)) {
            KtprdLog.w { "This does not look like a playready serve API (Server: ${server ?: "absent"})" }
        }
    }

    /**
     * @throws DeviceMismatchException if the server's device does not match [expectedSecurityLevel]
     */
    override suspend fun open(): ByteString {
        val data = request { client.get("$root/$deviceName/open") { authenticate() } }

        securityLevel = data["device"]?.jsonObject?.text("security_level")?.toIntOrNull()

        if (expectedSecurityLevel != null && expectedSecurityLevel != securityLevel) {
            throw DeviceMismatchException(
                "The Security Level specified ($expectedSecurityLevel) does not match the one in " +
                    "the API response (${securityLevel ?: "none"}).",
            )
        }

        val hex = data.text("session_id")
            ?: throw DecodeException("Remote PlayReady CDM did not return a session_id")
        return hex.decodeHexOrThrow("session_id")
    }

    override suspend fun close(sessionId: ByteString) {
        request { client.get("$root/$deviceName/close/${sessionId.hex()}") { authenticate() } }
    }

    override suspend fun getLicenseChallenge(
        sessionId: ByteString,
        wrmHeader: WrmHeader,
        revocationLists: List<Uuid>?,
    ): String {
        val data = request {
            client.post("$root/$deviceName/get_license_challenge") {
                authenticate()
                jsonBody {
                    put("session_id", sessionId.hex())
                    put("init_data", wrmHeader.xml)
                    revocationLists?.let { lists ->
                        put("rev_lists", buildJsonArray { lists.forEach { add(it.toString()) } })
                    }
                }
            }
        }

        return data.text("challenge")
            ?: throw DecodeException("Remote PlayReady CDM did not return a challenge")
    }

    override suspend fun parseLicense(sessionId: ByteString, licenseMessage: String) {
        request {
            client.post("$root/$deviceName/parse_license") {
                authenticate()
                jsonBody {
                    put("session_id", sessionId.hex())
                    put("license_message", licenseMessage)
                }
            }
        }
    }

    override suspend fun getKeys(sessionId: ByteString): List<PlayreadyKey> {
        val data = request {
            client.post("$root/$deviceName/get_keys") {
                authenticate()
                jsonBody { put("session_id", sessionId.hex()) }
            }
        }

        val keys = data["keys"] as? JsonArray ?: return emptyList()
        return keys.map { entry ->
            val key = entry.jsonObject
            PlayreadyKey(
                kid = key.text("key_id")?.decodeHexOrThrow("key_id")?.toByteArray()?.toUUID()
                    ?: throw DecodeException("Remote PlayReady CDM returned a key with no key_id"),
                key = key.text("key")?.decodeHexOrThrow("key")?.toByteArray()
                    ?: throw DecodeException("Remote PlayReady CDM returned a key with no key material"),
                keyType = PlayreadyKeyType.of(key.text("type")?.toIntOrNull() ?: 0),
                cipherType = PlayreadyCipherType.of(key.text("cipher_type")?.toIntOrNull() ?: 0),
                keyLength = key.text("key_length")?.toIntOrNull() ?: 0,
            )
        }
    }

    private fun HttpRequestBuilder.authenticate() {
        header("X-Secret-Key", secret)
    }

    private fun HttpRequestBuilder.jsonBody(build: JsonObjectBuilder.() -> Unit) {
        contentType(ContentType.Application.Json)
        setBody(buildJsonObject(build).toString())
    }

    /**
     * Run a call and unwrap the server's `{message, data}` body.
     *
     * Unlike pywidevine's protocol there is no status field in the body; the HTTP status is what
     * says whether the call succeeded.
     *
     * @return the `data` object, or an empty one for endpoints that return none
     * @throws RemotePlayreadyCdmException when the server replies with a non-2xx status
     */
    private suspend fun request(call: suspend () -> HttpResponse): JsonObject {
        val response = call()
        val body = response.bodyAsText()

        val envelope = try {
            json.parseToJsonElement(body).jsonObject
        } catch (e: Throwable) {
            if (!response.status.isSuccess()) {
                throw RemotePlayreadyCdmException(response.status.value, body.take(200))
            }
            throw DecodeException("Remote PlayReady CDM returned a body that is not a JSON object, $e")
        }

        if (!response.status.isSuccess()) {
            throw RemotePlayreadyCdmException(response.status.value, envelope.text("message") ?: "no message")
        }

        return envelope["data"] as? JsonObject ?: JsonObject(emptyMap())
    }

    /** JsonNull is a JsonPrimitive whose content is the text "null", so it must be excluded. */
    private fun JsonObject.text(key: String): String? = this[key]?.takeIf { it !is JsonNull }?.jsonPrimitive?.content

    private fun String.decodeHexOrThrow(field: String): ByteString = try {
        decodeHex()
    } catch (e: Throwable) {
        throw DecodeException("Remote PlayReady CDM returned a $field that is not hex, $e")
    }

    private fun io.ktor.http.HttpStatusCode.isSuccess(): Boolean = value in 200..299
}
