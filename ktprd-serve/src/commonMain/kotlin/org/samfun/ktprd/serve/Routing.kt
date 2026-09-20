@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd.serve

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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonObjectBuilder
import kotlinx.serialization.json.addJsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import kotlinx.serialization.json.putJsonArray
import kotlinx.serialization.json.putJsonObject
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import org.samfun.ktprd.cdm.PlayreadyCdm
import org.samfun.ktprd.core.PlayreadyDevice
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktvine.utils.KtvineException
import org.samfun.ktvine.utils.toHexString
import org.samfun.ktvine.utils.toLittleEndianByteArray
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Serve a ktprd CDM over the HTTP protocol `pyplayready serve` defines, so that either client —
 * `ktprd-remote`'s `RemotePlayreadyCdm` or pyplayready's — can drive it.
 *
 * This installs routes only; the caller owns the engine and may mount it anywhere:
 *
 * ```kotlin
 * embeddedServer(CIO, port = 7723) {
 *     routing { ktprdCdm(config) }
 * }.start(wait = true)
 * ```
 *
 * Callers authenticate with an `X-Secret-Key` header. A device's private keys never leave this
 * process, so treat the secret keys as credentials and serve this over TLS.
 */
public fun Route.ktprdCdm(config: PlayreadyServeConfig) {
    val registry = CdmRegistry(config)

    get("/") {
        call.identify(config)
        call.ok("OK")
    }

    // A client HEADs the root and reads the protocol version out of Server.
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

        post("/get_license_challenge") {
            call.withCdm(registry) { cdm ->
                val body = call.jsonBody() ?: return@withCdm
                val sessionId = call.bodySessionId(body) ?: return@withCdm

                val initData = body.text("init_data")
                    ?: return@withCdm call.fail(HttpStatusCode.BadRequest, "Missing required field 'init_data'.")

                // A client may send a raw WRMHEADER or a Base64 PSSH; both are accepted.
                val header = WrmHeader.from(initData)

                val revocationLists = (body["rev_lists"] as? JsonArray)
                    ?.mapNotNull { runCatching { Uuid.parse(it.jsonPrimitive.content) }.getOrNull() }

                val challenge = cdm.getLicenseChallenge(sessionId, header, revocationLists)
                call.ok("Success") { put("challenge", challenge) }
            }
        }

        post("/parse_license") {
            call.withCdm(registry) { cdm ->
                val body = call.jsonBody() ?: return@withCdm
                val sessionId = call.bodySessionId(body) ?: return@withCdm

                val message = body.text("license_message")
                    ?: return@withCdm call.fail(
                        HttpStatusCode.BadRequest,
                        "Missing required field 'license_message'.",
                    )

                cdm.parseLicense(sessionId, message)
                call.ok("Successfully parsed and loaded the Keys from the License message.")
            }
        }

        post("/get_keys") {
            call.withCdm(registry) { cdm ->
                val body = call.jsonBody() ?: return@withCdm
                val sessionId = call.bodySessionId(body) ?: return@withCdm

                val keys = cdm.getKeys(sessionId)
                call.ok("Success") {
                    putJsonArray("keys") {
                        keys.forEach { key ->
                            addJsonObject {
                                // The wire format carries the key id as the GUID PlayReady stores,
                                // not the big-endian form ktprd holds in memory.
                                put("key_id", key.kid.toLittleEndianByteArray().toHexString())
                                put("key", key.key.toHexString())
                                put("type", key.keyType.value)
                                put("cipher_type", key.cipherType.value)
                                put("key_length", key.keyLength)
                            }
                        }
                    }
                }
            }
        }
    }
}

/** One [PlayreadyCdm] per (secret key, device), so users never share sessions. */
private class CdmRegistry(private val config: PlayreadyServeConfig) {
    private val lock = Mutex()
    private val cdms = mutableMapOf<Pair<String, String>, PlayreadyCdm>()

    suspend fun of(secretKey: String, deviceName: String, device: PlayreadyDevice): PlayreadyCdm =
        lock.withLock { cdms.getOrPut(secretKey to deviceName) { PlayreadyCdm.fromDevice(device) } }

    fun config(): PlayreadyServeConfig = config
}

/**
 * Authenticate, authorise the device, and translate any [KtvineException] into an envelope.
 *
 * Unknown device names are not distinguished from unauthorised ones in the 403, so a caller
 * cannot discover which devices exist by guessing.
 */
private suspend fun ApplicationCall.withCdm(registry: CdmRegistry, block: suspend (PlayreadyCdm) -> Unit) {
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

private fun ApplicationCall.identify(config: PlayreadyServeConfig) {
    response.header(HttpHeaders.Server, config.serverHeader)
}

private val json = Json { ignoreUnknownKeys = true }

private suspend fun ApplicationCall.jsonBody(): JsonObject? = try {
    json.parseToJsonElement(receiveText()) as JsonObject
} catch (_: Throwable) {
    fail(HttpStatusCode.BadRequest, "Body must be a JSON object.")
    null
}

private fun JsonObject.text(key: String): String? =
    this[key]?.let { runCatching { it.jsonPrimitive.content }.getOrNull() }?.takeIf { it.isNotEmpty() }

private suspend fun ApplicationCall.pathSessionId(): ByteString? = decodeSession(parameters["session_id"])

private suspend fun ApplicationCall.bodySessionId(body: JsonObject): ByteString? = decodeSession(
    body.text("session_id"),
)

private suspend fun ApplicationCall.decodeSession(hex: String?): ByteString? {
    val decoded = hex?.let { runCatching { it.decodeHex() }.getOrNull() }
    if (decoded == null) fail(HttpStatusCode.BadRequest, "Missing or malformed 'session_id'.")
    return decoded
}

private suspend fun ApplicationCall.ok(message: String, data: (JsonObjectBuilder.() -> Unit)? = null) {
    val payload = buildJsonObject {
        put("message", message)
        if (data != null) putJsonObject("data", data)
    }
    respondText(payload.toString(), ContentType.Application.Json, HttpStatusCode.OK)
}

private suspend fun ApplicationCall.fail(status: HttpStatusCode, message: String) {
    val payload = buildJsonObject { put("message", message) }
    respondText(payload.toString(), ContentType.Application.Json, status)
}
