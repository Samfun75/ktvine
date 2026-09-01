@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine.remote

import io.ktor.client.HttpClient
import io.ktor.client.request.HttpRequestBuilder
import io.ktor.client.request.get
import io.ktor.client.request.header
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.HttpResponse
import io.ktor.client.statement.bodyAsText
import io.ktor.http.ContentType
import io.ktor.http.contentType
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.cdm.CdmApi
import org.samfun.ktvine.core.Key
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.LicenseType
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.utils.DeviceMismatchException
import org.samfun.ktvine.utils.KtvineException
import org.samfun.ktvine.utils.ValueException
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** A remote CDM server rejected a request. [status] is the status field from its JSON body. */
public class RemoteCdmException(
    public val status: Int,
    public val serverMessage: String,
) : KtvineException("Remote CDM returned $status: $serverMessage")

/**
 * A [CdmApi] backed by a pywidevine-compatible CDM server (`pywidevine serve`).
 *
 * The device's private key never reaches this process — every operation is an HTTP call, so
 * one server can hold the device while many clients use it.
 *
 * The caller supplies the [HttpClient], which keeps this module free of any engine choice:
 *
 * ```kotlin
 * val cdm = RemoteCdm(
 *     client = HttpClient(CIO),
 *     baseUrl = "https://cdm.example.com",
 *     deviceName = "generic_android_device",
 *     secret = "your-api-key",
 * )
 * ```
 *
 * @param baseUrl the server root, with or without a trailing slash
 * @param deviceName the device the server should use, as named in its config
 * @param secret the value sent as the `X-Secret-Key` header
 * @param expectedSystemId if given, [open] rejects a server whose device reports a
 *   different Widevine system id
 * @param expectedSecurityLevel if given, [open] rejects a server whose device reports a
 *   different security level
 */
public class RemoteCdm(
    private val client: HttpClient,
    baseUrl: String,
    private val deviceName: String,
    private val secret: String,
    private val expectedSystemId: Int? = null,
    private val expectedSecurityLevel: Int? = null,
) : CdmApi {

    private val root: String = baseUrl.trimEnd('/')
    private val json = Json { ignoreUnknownKeys = true }

    /** System id the server reports for [deviceName]. Populated by the first [open]. */
    public var systemId: Int? = null
        private set

    /** Security level the server reports for [deviceName]. Populated by the first [open]. */
    public var securityLevel: Int? = null
        private set

    /**
     * @throws DeviceMismatchException if the server's device does not match
     *   [expectedSystemId] or [expectedSecurityLevel], when either was given
     */
    override suspend fun open(): ByteString {
        val data = request { client.get("$root/$deviceName/open") { authenticate() } }

        data["device"]?.jsonObject?.let { device ->
            systemId = device.text("system_id")?.toIntOrNull()
            securityLevel = device.text("security_level")?.toIntOrNull()
        }

        // pywidevine rejects the same two fields here (remotecdm.py:108).
        verify("System ID", expectedSystemId, systemId)
        verify("Security Level", expectedSecurityLevel, securityLevel)

        val hex = data.text("session_id")
            ?: throw DecodeException("Remote CDM did not return a session_id")
        return hex.decodeHexOrThrow("session_id")
    }

    override suspend fun close(sessionId: ByteString) {
        request { client.get("$root/$deviceName/close/${sessionId.hex()}") { authenticate() } }
    }

    override suspend fun setServiceCertificate(sessionId: ByteString, certificateBase64: String?): String? {
        val data = request {
            client.post("$root/$deviceName/set_service_certificate") {
                authenticate()
                jsonBody {
                    put("session_id", sessionId.hex())
                    // pywidevine reads a null certificate as "clear the current one".
                    if (certificateBase64 == null) {
                        put(
                            "certificate",
                            JsonNull,
                        )
                    } else {
                        put("certificate", certificateBase64)
                    }
                }
            }
        }
        return data.text("provider_id")
    }

    override suspend fun getServiceCertificateBase64(sessionId: ByteString): String? {
        val data = request {
            client.post("$root/$deviceName/get_service_certificate") {
                authenticate()
                jsonBody { put("session_id", sessionId.hex()) }
            }
        }
        return data.text("service_certificate")
    }

    override suspend fun getLicenseChallenge(
        sessionId: ByteString,
        pssh: PSSH,
        licenseType: LicenseType,
        privacyMode: Boolean,
        requestType: LicenseRequest.RequestType,
    ): ByteArray {
        if (requestType != LicenseRequest.RequestType.NEW) {
            throw ValueException("A remote CDM server only issues NEW license requests, not $requestType.")
        }

        val data = request {
            client.post("$root/$deviceName/get_license_challenge/${licenseType.name}") {
                authenticate()
                jsonBody {
                    put("session_id", sessionId.hex())
                    put("init_data", pssh.exportBase64())
                    put("privacy_mode", privacyMode)
                }
            }
        }

        val challenge = data.text("challenge_b64")
            ?: throw DecodeException("Remote CDM did not return a challenge_b64")
        return challenge.decodeBase64()?.toByteArray()
            ?: throw DecodeException("Remote CDM returned a challenge_b64 that is not Base64")
    }

    override suspend fun parseLicense(sessionId: ByteString, licenseMessage: ByteArray) {
        request {
            client.post("$root/$deviceName/parse_license") {
                authenticate()
                jsonBody {
                    put("session_id", sessionId.hex())
                    put("license_message", licenseMessage.toByteString().base64())
                }
            }
        }
    }

    override suspend fun getKeys(sessionId: ByteString, type: License.KeyContainer.KeyType?): List<Key> {
        // pywidevine spells "every type" as ALL.
        val data = request {
            client.post("$root/$deviceName/get_keys/${type?.name ?: "ALL"}") {
                authenticate()
                jsonBody { put("session_id", sessionId.hex()) }
            }
        }

        val keys = data["keys"]?.jsonArray
            ?: throw DecodeException("Remote CDM did not return a keys array")

        return keys.map { entry ->
            val key = entry.jsonObject
            val keyType = key.text("type")
                ?: throw DecodeException("A returned key has no type")

            Key(
                type = runCatching { License.KeyContainer.KeyType.valueOf(keyType) }.getOrNull()
                    ?: throw DecodeException("A returned key has an unknown type '$keyType'"),
                kid = key.text("key_id")?.let { hex ->
                    runCatching { Uuid.parseHex(hex) }.getOrNull()
                        ?: throw DecodeException("A returned key has a key_id that is not hex: $hex")
                } ?: throw DecodeException("A returned key has no key_id"),
                key = key.text("key")?.decodeHexOrThrow("key")?.toByteArray()
                    ?: throw DecodeException("A returned key has no key"),
                permissions = key["permissions"]?.jsonArray
                    ?.mapNotNull { entry -> entry.takeIf { it !is JsonNull }?.jsonPrimitive?.content }
                    ?: emptyList(),
            )
        }
    }

    private fun verify(what: String, expected: Int?, reported: Int?) {
        if (expected == null || expected == reported) return
        throw DeviceMismatchException(
            "The $what specified ($expected) does not match the one in the API response (${reported ?: "none"}).",
        )
    }

    private fun HttpRequestBuilder.authenticate() {
        header("X-Secret-Key", secret)
    }

    private fun HttpRequestBuilder.jsonBody(build: JsonObjectBuilder.() -> Unit) {
        contentType(ContentType.Application.Json)
        setBody(buildJsonObject(build).toString())
    }

    /**
     * Run a call and unwrap pywidevine's `{status, message, data}` envelope.
     *
     * @return the `data` object, or an empty one for endpoints that return none
     * @throws RemoteCdmException when `status` is not 200
     * @throws DecodeException when the body is not the expected envelope
     */
    private suspend fun request(call: suspend () -> HttpResponse): JsonObject {
        val body = call().bodyAsText()

        val envelope = try {
            json.parseToJsonElement(body).jsonObject
        } catch (e: Throwable) {
            throw DecodeException("Remote CDM returned a body that is not a JSON object, $e")
        }

        val status = envelope.text("status")?.toIntOrNull()
            ?: throw DecodeException("Remote CDM response has no status field")
        if (status != 200) {
            throw RemoteCdmException(status, envelope.text("message") ?: "no message")
        }

        // Endpoints that return nothing omit "data" entirely, or send an explicit null.
        return envelope["data"] as? JsonObject ?: JsonObject(emptyMap())
    }

    /** JsonNull is a JsonPrimitive whose content is the text "null", so it must be excluded. */
    private fun JsonObject.text(key: String): String? = this[key]?.takeIf { it !is JsonNull }?.jsonPrimitive?.content

    private fun String.decodeHexOrThrow(field: String): ByteString = try {
        decodeHex()
    } catch (e: Throwable) {
        throw DecodeException("Remote CDM returned a $field that is not hex, $e")
    }
}
