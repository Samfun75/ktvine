package org.samfun.ktvine.serve

import io.ktor.http.ContentType
import io.ktor.http.HttpHeaders
import io.ktor.http.HttpStatusCode
import io.ktor.server.application.ApplicationCall
import io.ktor.server.request.receiveText
import io.ktor.server.response.header
import io.ktor.server.response.respondText
import io.ktor.server.routing.Route
import io.ktor.server.routing.get
import io.ktor.server.routing.head
import io.ktor.server.routing.post
import io.ktor.server.routing.route
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonObject
import okio.ByteString
import okio.ByteString.Companion.decodeBase64
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseType
import org.samfun.ktvine.utils.KtvineException
import org.samfun.ktvine.utils.toHexString

/**
 * Serve a ktvine CDM over the HTTP protocol pywidevine's `serve` command defines, so that
 * either client — ktvine's `RemoteCdm` or pywidevine's — can drive it.
 *
 * This installs routes only; the caller owns the engine and may mount it anywhere:
 *
 * ```kotlin
 * embeddedServer(CIO, port = 8786) {
 *     routing { ktvineCdm(config) }
 * }.start(wait = true)
 * ```
 *
 * Callers authenticate with an `X-Secret-Key` header. A device's private key never leaves
 * this process, so treat the secret keys as credentials and serve this over TLS.
 */
public fun Route.ktvineCdm(config: ServeConfig) {
    val registry = CdmRegistry(config)

    get("/") {
        call.identify(config)
        call.ok("Pong!")
    }

    // pywidevine's client HEADs the root and reads the protocol version out of Server.
    head("/") {
        call.identify(config)
        call.respondText("", ContentType.Application.Json, HttpStatusCode.OK)
    }

    route("/{device}") {
        get("/open") {
            call.withCdm(registry) { cdm ->
                val sessionId = cdm.open()
                call.ok("Success") {
                    put("session_id", sessionId.hex())
                    putJsonObject("device") {
                        put("system_id", cdm.systemId)
                        put("security_level", cdm.securityLevel)
                    }
                }
            }
        }

        get("/close/{session_id}") {
            call.withCdm(registry) { cdm ->
                val sessionId = call.pathSessionId() ?: return@withCdm
                cdm.close(sessionId)
                call.ok("Successfully closed Session '${sessionId.hex()}'.")
            }
        }

        post("/set_service_certificate") {
            call.withCdm(registry) { cdm ->
                val body = call.jsonBody() ?: return@withCdm
                val sessionId = call.bodySessionId(body) ?: return@withCdm
                // An explicit null clears the certificate and reports the previous provider.
                val certificate = body["certificate"]?.let {
                    if (it is JsonPrimitive && !it.isString) null else it.jsonPrimitive.content
                }
                val providerId = cdm.setServiceCertificate(sessionId, certificate)
                call.ok("Successfully set the Service Certificate.") {
                    put("provider_id", providerId)
                }
            }
        }

        post("/get_service_certificate") {
            call.withCdm(registry) { cdm ->
                val body = call.jsonBody() ?: return@withCdm
                val sessionId = call.bodySessionId(body) ?: return@withCdm
                val certificate = cdm.getServiceCertificateBase64(sessionId)
                call.ok("Successfully got the Service Certificate.") {
                    put("service_certificate", certificate)
                }
            }
        }

        post("/get_license_challenge/{license_type}") {
            call.withCdm(registry) { cdm ->
                val body = call.jsonBody() ?: return@withCdm
                val sessionId = call.bodySessionId(body) ?: return@withCdm

                val typeName = call.parameters["license_type"].orEmpty()
                val licenseType = LicenseType.entries.firstOrNull { it.name == typeName }
                    ?: return@withCdm call.fail(HttpStatusCode.BadRequest, "Invalid license type '$typeName'.")

                val initData = body["init_data"]?.jsonPrimitive?.content
                    ?: return@withCdm call.fail(HttpStatusCode.BadRequest, "Missing 'init_data'.")
                val privacyMode = body["privacy_mode"]?.jsonPrimitive?.content?.toBoolean() ?: true

                if (config.forcePrivacyMode) {
                    if (!privacyMode || cdm.getServiceCertificateBase64(sessionId) == null) {
                        return@withCdm call.fail(
                            HttpStatusCode.Forbidden,
                            "No Service Certificate set but Privacy Mode is Enforced.",
                        )
                    }
                }

                val pssh = PSSH(initData)
                val challenge = cdm.getLicenseChallenge(sessionId, pssh, licenseType, privacyMode)
                call.ok("Success") { put("challenge_b64", challenge.toByteString().base64()) }
            }
        }

        post("/parse_license") {
            call.withCdm(registry) { cdm ->
                val body = call.jsonBody() ?: return@withCdm
                val sessionId = call.bodySessionId(body) ?: return@withCdm
                val message = body["license_message"]?.jsonPrimitive?.content
                    ?: return@withCdm call.fail(HttpStatusCode.BadRequest, "Missing 'license_message'.")

                val decoded = message.decodeBase64OrNull()
                    ?: return@withCdm call.fail(HttpStatusCode.BadRequest, "'license_message' is not Base64.")

                cdm.parseLicense(sessionId, decoded)
                call.ok("Successfully parsed and loaded the Keys from the License message.")
            }
        }

        post("/get_keys/{key_type}") {
            call.withCdm(registry) { cdm ->
                val body = call.jsonBody() ?: return@withCdm
                val sessionId = call.bodySessionId(body) ?: return@withCdm

                val typeName = call.parameters["key_type"].orEmpty()
                // pywidevine spells "every type" as ALL, and so does ktvine's client.
                val filter = if (typeName == "ALL") {
                    null
                } else {
                    License.KeyContainer.KeyType.entries.firstOrNull { it.name == typeName }
                        ?: return@withCdm call.fail(HttpStatusCode.BadRequest, "Invalid key type '$typeName'.")
                }

                val keys = cdm.getKeys(sessionId, filter)
                call.ok("Success") {
                    put(
                        "keys",
                        buildJsonArray {
                            keys.forEach { key ->
                                add(
                                    buildJsonObject {
                                        put("key_id", key.kid.toHexString())
                                        put("key", key.key.toHexString())
                                        put("type", key.type.name)
                                        put(
                                            "permissions",
                                            buildJsonArray { key.permissions.forEach { add(JsonPrimitive(it)) } },
                                        )
                                    },
                                )
                            }
                        },
                    )
                }
            }
        }
    }
}

/** One [Cdm] per (secret key, device), so users never share sessions. */
private class CdmRegistry(private val config: ServeConfig) {
    private val lock = Mutex()
    private val cdms = mutableMapOf<Pair<String, String>, Cdm>()

    suspend fun of(secretKey: String, deviceName: String, device: org.samfun.ktvine.core.Device): Cdm =
        lock.withLock { cdms.getOrPut(secretKey to deviceName) { Cdm.fromDevice(device) } }

    fun config(): ServeConfig = config
}

/**
 * Authenticate, authorise the device, and translate any [KtvineException] into an envelope.
 *
 * Device names are not distinguished from unauthorised ones in the 403, so a caller cannot
 * discover which devices exist by guessing.
 */
private suspend fun ApplicationCall.withCdm(registry: CdmRegistry, block: suspend (Cdm) -> Unit) {
    val config = registry.config()
    identify(config)
    val secretKey = request.headers["X-Secret-Key"]
    val user = config.userFor(secretKey)
        ?: return fail(HttpStatusCode.Unauthorized, "Secret Key is invalid or was not provided.")

    val deviceName = parameters["device"].orEmpty()
    val device = config.deviceFor(user, deviceName)
        ?: return fail(HttpStatusCode.Forbidden, "Device '$deviceName' is not found or you may not use it.")

    try {
        block(registry.of(secretKey!!, deviceName, device))
    } catch (e: KtvineException) {
        fail(HttpStatusCode.BadRequest, e.message ?: e::class.simpleName.orEmpty())
    }
}

private fun ApplicationCall.identify(config: ServeConfig) {
    response.header(HttpHeaders.Server, config.serverHeader)
}

private val json = Json { ignoreUnknownKeys = true }

private suspend fun ApplicationCall.jsonBody(): JsonObject? = try {
    json.parseToJsonElement(receiveText()) as JsonObject
} catch (_: Throwable) {
    fail(HttpStatusCode.BadRequest, "Body must be a JSON object.")
    null
}

private suspend fun ApplicationCall.pathSessionId(): ByteString? = decodeSession(parameters["session_id"])

private suspend fun ApplicationCall.bodySessionId(body: JsonObject): ByteString? =
    decodeSession(body["session_id"]?.jsonPrimitive?.content)

private suspend fun ApplicationCall.decodeSession(hex: String?): ByteString? {
    val decoded = hex?.let { runCatching { it.decodeHex() }.getOrNull() }
    if (decoded == null) fail(HttpStatusCode.BadRequest, "Missing or malformed 'session_id'.")
    return decoded
}

private suspend fun ApplicationCall.ok(message: String, data: (JsonObjectBuilder.() -> Unit)? = null) {
    val payload = buildJsonObject {
        put("status", 200)
        put("message", message)
        if (data != null) putJsonObject("data", data)
    }
    respondText(payload.toString(), ContentType.Application.Json, HttpStatusCode.OK)
}

private suspend fun ApplicationCall.fail(status: HttpStatusCode, message: String) {
    val payload = buildJsonObject {
        put("status", status.value)
        put("message", message)
    }
    respondText(payload.toString(), ContentType.Application.Json, status)
}

private fun String.decodeBase64OrNull(): ByteArray? = decodeBase64()?.toByteArray()
