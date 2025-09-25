package org.samfun.ktvine

import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import okio.Buffer
import org.mp4parser.PropertyBoxParserImpl
import org.mp4parser.tools.ByteBufferByteChannel
import org.samfun.ktvine.proto.WidevinePsshData
import java.io.ByteArrayOutputStream
import java.nio.channels.Channels
import java.nio.channels.WritableByteChannel
import java.util.Base64
import java.util.UUID


class PSSH {

    private var _version: Int = 0
    private var _flags: Int = 0
    private var _keyIds: List<UUID> = listOf()
    private var _systemId: ByteArray = PsshBox.WIDEVINE
    private var _content: ByteArray = ByteArray(0)


    constructor(data: String) {
        val decoded = Base64
            .getDecoder()
            .decode(data)
        val box = parseBox(decoded)
        init(box)
    }

    constructor(data: ByteArray) {
        val box = parseBox(data)
        init(box)
    }

    constructor(box: PsshBox) {
        init(box)
    }

    private fun init(data: PsshBox) {
        try { data.parseDetails() } catch (_: Throwable) {}

        _systemId = data.systemId
        _flags = data.flags
        _version = data.version
        _content = data.content
        _keyIds = data.keyIds
    }

    private fun parseBox(data: ByteArray): PsshBox = try {
        PropertyBoxParserImpl()
            .parseBox(
                ByteBufferByteChannel(data), null
            ) as PsshBox
    } catch (_: Throwable) {
        val psshData = try { WidevinePsshData.ADAPTER.decode(data) } catch (_: Throwable) { null }
        if (psshData != null && psshData.encode().size == data.size) {
            PsshBox(PsshBox.WIDEVINE, psshData.encode())
        } else {
            val plText = "</WRMHEADER>".toByteArray(Charsets.UTF_16LE).toHexString()
            if (data.copyOf().toHexString().contains(plText)) {
                PsshBox(PsshBox.PLAYREADY_SYSTEM_ID, data)
            } else {
                PsshBox(PsshBox.WIDEVINE, data)
            }
        }
    }

    /**
     * Get all Key IDs from within the Box or Init Data, wherever possible.
     *
     * Supports:
     * - Version 1 PSSH Boxes
     * - WidevineCencHeaders
     * - PlayReadyHeaders (4.0.0.0->4.3.0.0)
     */
    fun key_ids(): List<UUID> {
        if (_version == 1 && _keyIds.isNotEmpty()) return _keyIds

        // 1) Try Widevine CENC header regardless of system_id (lenient like Python)
        try {
            val header = WidevinePsshData.ADAPTER.decode(_content)
            return header.key_ids.map {
                when (it.size) {
                    16 -> it.uuidFromByteString()
                    32 -> it.uuidFromHexByteString() // stored as hex
                    else -> it.uuidFromByteArray() // assuming stored as number
                }
            }
        } catch (_: Throwable) {
            // ignore and try PlayReady
        }

        // 2) Try PlayReadyObject (PRO)
        try {
            val proData = Buffer().write(_content)
            val size = proData.readIntLe()
            if (size == _content.size) {
                val proRecordCount = proData.readShortLe().toInt() and 0xFFFF
                repeat(proRecordCount) {
                    val prrType = proData.readShortLe().toInt() and 0xFFFF
                    val prrLength = proData.readShortLe().toInt() and 0xFFFF
                    val prrValue = proData.readByteArray(prrLength.toLong())
                    if (prrType != 0x01) return@repeat

                    val xml = String(prrValue, Charsets.UTF_16LE)
                    val version = Regex("""version=\"([^\"]+)\"""").find(xml)?.groupValues?.get(1)
                        ?: throw ValueException("Unsupported PlayReadyHeader, missing version")

                    val keyIdsB64: List<String> = when (version) {
                        "4.0.0.0" -> Regex("""<KID[^>]*>([^<]+)</KID>""", RegexOption.IGNORE_CASE)
                            .findAll(xml)
                            .map { it.groupValues[1].trim() }
                            .toList()
                        "4.1.0.0", "4.2.0.0", "4.3.0.0" -> Regex("""<KID\b[^>]*\bVALUE=\"([^\"]+)\"""", RegexOption.IGNORE_CASE)
                            .findAll(xml)
                            .map { it.groupValues[1].trim() }
                            .toList()
                        else -> throw ValueException("Unsupported PlayReadyHeader version $version")
                    }

                    return keyIdsB64.map { b64 ->
                        Base64.getDecoder().decode(b64).toByteString().uuidFromByteString()
                    }
                }
            }
        } catch (_: Throwable) {
            // ignore and continue
        }

        // 3) Fallback: if v1 PSSH and key IDs present in box
        if (_version == 1 && _keyIds.isNotEmpty()) return _keyIds

        throw ValueException("This PSSH is not supported by key_ids(), ${dumps()}")
    }

    fun dump(): ByteArray {
        // Export the PSSH object as a full PSSH box in bytes form.
        val box = PsshBox().apply {
            version = _version
            flags = _flags
            systemId = _systemId
            content = _content
            keyIds = if (_version == 1 && _keyIds.isNotEmpty()) _keyIds else listOf()
        }

        val byteArrayOutputStream = ByteArrayOutputStream()
        val channel: WritableByteChannel = Channels.newChannel(byteArrayOutputStream)

        box.getBox(channel)
        return byteArrayOutputStream.toByteArray()
    }

    fun dumps(): String {
        // Export the PSSH object as a full PSSH box in base64 form.
        return Base64.getEncoder().encodeToString(dump())
    }

    override fun toString(): String = dumps()

    // Convert PlayReady PSSH to Widevine PSSH
    fun to_widevine() {
        if (_systemId.contentEquals(PsshBox.WIDEVINE)) throw ValueException("This is already a Widevine PSSH")

        val kids = key_ids()
        val widevine = WidevinePsshData(
            key_ids = kids.map { it.toByteArray().toByteString() },
            algorithm = WidevinePsshData.Algorithm.AESCTR
        )

        if (_version == 1) _keyIds = kids
        _content = widevine.encode()
        _systemId = PsshBox.WIDEVINE
    }

    // Convert Widevine PSSH to PlayReady v4.3.0.0 PSSH
    fun to_playready(
        la_url: String? = null,
        lui_url: String? = null,
        ds_id: ByteArray? = null,
        decryptor_setup: String? = null,
        custom_data: String? = null
    ) {
        if (_systemId.contentEquals(PsshBox.PLAYREADY_SYSTEM_ID)) throw ValueException("This is already a PlayReady PSSH")

        val keyIdsXml = key_ids().joinToString("") { kid ->
            val b64 = Base64.getEncoder().encodeToString(kid.toByteArray())
            """
            <KID ALGID="AESCTR" VALUE="$b64"></KID>
            """.trimIndent()
        }

        val prrValue = """
        <WRMHEADER xmlns="http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader" version="4.3.0.0">
            <DATA>
                <PROTECTINFO>
                    <KIDS>$keyIdsXml</KIDS>
                </PROTECTINFO>
                ${la_url?.let { "<LA_URL>$it</LA_URL>" } ?: ""}
                ${lui_url?.let { "<LUI_URL>$it</LUI_URL>" } ?: ""}
                ${ds_id?.let { "<DS_ID>${Base64.getEncoder().encodeToString(it)}</DS_ID>" } ?: ""}
                ${decryptor_setup?.let { "<DECRYPTORSETUP>$it</DECRYPTORSETUP>" } ?: ""}
                ${custom_data?.let { "<CUSTOMATTRIBUTES xmlns=\"\">$it</CUSTOMATTRIBUTES>" } ?: ""}
            </DATA>
        </WRMHEADER>
        """.trimIndent().toByteArray(Charsets.UTF_16LE)

        val body = ByteArrayOutputStream().apply {
            write(leU16(1))              // record count
            write(leU16(0x01))           // type: PlayReadyHeader
            write(leU16(prrValue.size))  // length
            write(prrValue)
        }.toByteArray()

        val pro = ByteArrayOutputStream().apply {
            write(leU32(body.size + 4))  // total size including this length field
            write(body)
        }.toByteArray()

        _content = pro
        _systemId = PsshBox.PLAYREADY_SYSTEM_ID
    }

    // Only for Widevine PSSH: overwrite Key IDs in both WV header and, if v1, box field too
    fun set_key_ids(keyIds: List<UUID>) {
        if (!_systemId.contentEquals(PsshBox.WIDEVINE))
            throw ValueException("Only Widevine PSSH Boxes are supported, not ${_systemId.toHexString()}")

        if (_version == 1 || _keyIds.isNotEmpty()) _keyIds = keyIds

        val cenc = if (_content.isEmpty()) WidevinePsshData() else WidevinePsshData.ADAPTER.decode(_content)
        val updated = cenc.copy(
            key_ids = keyIds.map { it.toByteArray().toByteString() }
        )
        _content = updated.encode()
    }

    // Overload accepting UUID | String(hex/base64) | ByteArray like Python's parse
    fun set_key_ids_any(keyIds: List<Any>) = set_key_ids(parse_key_ids(keyIds))

    companion object {
        // Convert a list of UUID | String(hex/base64) | ByteArray to UUIDs
        fun parse_key_ids(key_ids: List<Any>): List<UUID> {
            require(key_ids.all { it is UUID || it is String || it is ByteArray }) { "Some items of key_ids are not a UUID, String, or ByteArray." }
            return key_ids.map { item ->
                when (item) {
                    is UUID -> item
                    is String -> {
                        val isHex = item.all { it in ('0'..'9') || it in ('a'..'f') || it in ('A'..'F') }
                        val bytes = if (isHex) item.decodeHex().toByteArray() else Base64.getDecoder().decode(item)
                        bytes.toByteString().uuidFromByteString()
                    }
                    is ByteArray -> item.toByteString().uuidFromByteString()
                    else -> error("unreachable")
                }
            }
        }

        fun new(
            system_id: UUID,
            key_ids: List<UUID>? = null,
            init_data: Any? = null,
            version: Int = 0,
            flags: Int = 0
        ): PSSH {
            require(version in 0..1) { "Invalid version, must be either 0 or 1, not $version." }
            require(flags >= 0) { "Invalid flags, cannot be less than 0." }

            if (version == 0 && key_ids != null && init_data != null)
                throw ValueException("Version 0 PSSH boxes must use only init_data, not init_data and key_ids.")
            if (version == 1 && key_ids == null && init_data == null)
                throw ValueException("Version 1 PSSH boxes must use either init_data or key_ids but neither were provided")

            val contentBytes: ByteArray = when (init_data) {
                null -> ByteArray(0)
                is WidevinePsshData -> init_data.encode()
                is String -> {
                    val isHex = init_data.all { it in ('0'..'9') || it in ('a'..'f') || it in ('A'..'F') }
                    if (isHex) init_data.decodeHex().toByteArray() else Base64.getDecoder().decode(init_data)
                }
                is ByteArray -> init_data
                else -> throw ValueException("Expecting init_data to be WidevinePsshData, hex, base64, or bytes, not ${init_data::class}")
            }

            val box = PsshBox().apply {
                this.version = version
                this.flags = flags
                this.systemId = system_id.toByteArray()
                this.content = contentBytes
                this.keyIds = emptyList()
            }

            val pssh = PSSH(box)
            if (key_ids != null) {
                pssh._version = version // reinforce in case
                pssh.set_key_ids(key_ids)
            }
            return pssh
        }
    }
}

// Little-endian helpers
private fun leU16(v: Int): ByteArray = byteArrayOf((v and 0xFF).toByte(), ((v ushr 8) and 0xFF).toByte())
private fun leU32(v: Int): ByteArray = byteArrayOf(
    (v and 0xFF).toByte(),
    ((v ushr 8) and 0xFF).toByte(),
    ((v ushr 16) and 0xFF).toByte(),
    ((v ushr 24) and 0xFF).toByte()
)
