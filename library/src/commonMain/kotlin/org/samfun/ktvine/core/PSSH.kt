package org.samfun.ktvine.core

import co.touchlab.kermit.Logger
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import okio.Buffer
import org.mp4parser.PropertyBoxParserImpl
import org.mp4parser.tools.ByteBufferByteChannel
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.proto.WidevinePsshData
import org.samfun.ktvine.utils.PsshBox
import org.samfun.ktvine.utils.decodeToStringUtf16LE
import org.samfun.ktvine.utils.encodeToUtf16LE
import org.samfun.ktvine.utils.toByteArray
import org.samfun.ktvine.utils.toHexString
import org.samfun.ktvine.utils.toLEU16
import org.samfun.ktvine.utils.toLEU32
import org.samfun.ktvine.utils.uuidFromByteArray
import org.samfun.ktvine.utils.uuidFromByteString
import org.samfun.ktvine.utils.uuidFromHexByteString
import java.io.ByteArrayOutputStream
import java.nio.channels.Channels
import java.nio.channels.WritableByteChannel
import java.util.UUID
import kotlin.io.encoding.Base64

/**
 * Helper for parsing and building PSSH (Protection System Specific Header) boxes.
 * Supports both Widevine and PlayReady headers and provides conversions.
 */
class PSSH {

    private var _version: Int = 0
    private var _flags: Int = 0
    private var _keyIds: List<UUID> = listOf()
    private var _systemId: ByteArray = PsshBox.WIDEVINE
    private var _content: ByteArray = ByteArray(0)

    /** Raw init data contained within the PSSH box. */
    val initData: ByteArray get() = _content

    /** Create from a Base64-encoded PSSH box or header bytes. */
    constructor(data: String) {
        val decoded = Base64.decode(data)
        val box = parseBox(decoded)
        init(box)
    }

    /** Create from raw bytes of a PSSH box or header bytes. */
    constructor(data: ByteArray) {
        val box = parseBox(data)
        init(box)
    }

    /** Create directly from a parsed [PsshBox]. */
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
        Logger.i("ktvine") { "Attempting to parse data as full PSSH box... ${data.toHexString()}" }
        (PropertyBoxParserImpl()
            .parseBox(
                ByteBufferByteChannel(data), null
            ) as PsshBox).also {
                Logger.i("ktvine") { "Parsed data as full PSSH box: ${it.isParsed()}" }
            }
    } catch (e: Throwable) {
        Logger.w("ktvine") {
            "Error parsing PSSH box structure, assuming raw init data. Error: ${e.message}"
        }
        val psshData = try { WidevinePsshData.ADAPTER.decode(data) } catch (_: Throwable) { null }
        if (psshData != null && psshData.encode().size == data.size) {
            Logger.i("ktvine") { "Parsed raw data as Widevine PSSH." }
            PsshBox(PsshBox.WIDEVINE, psshData.encode())
        } else {
            Logger.w("ktvine") { "Could not parse raw data as Widevine PSSH, checking for PlayReady." }
            val plText = "</WRMHEADER>".encodeToUtf16LE().toHexString()
            if (data.copyOf().toHexString().contains(plText)) {
                Logger.i("ktvine") { "Parsed raw data as PlayReady PSSH." }
                PsshBox(PsshBox.PLAYREADY_SYSTEM_ID, data)
            } else {
                Logger.i("ktvine") { "Defaulting to Widevine PSSH for raw data." }
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
    fun keyIds(): List<UUID> {
        if (_version == 1 && _keyIds.isNotEmpty()) return _keyIds

        // 1) Try Widevine CENC header regardless of system_id
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

                    val xml = prrValue.decodeToStringUtf16LE()
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
                        Base64.decode(b64).toByteString().uuidFromByteString()
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

    /** Export the PSSH object as a full PSSH box in bytes form. */
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

    /** Export the PSSH object as a full PSSH box in Base64 form. */
    fun dumps(): String {
        // Export the PSSH object as a full PSSH box in base64 form.
        return Base64.encode(dump())
    }

    override fun toString(): String = dumps()

    /** Convert PlayReady PSSH to a Widevine PSSH. */
    fun toWidevine() {
        if (_systemId.contentEquals(PsshBox.WIDEVINE)) throw ValueException("This is already a Widevine PSSH")

        val kids = keyIds()
        val widevine = WidevinePsshData(
            key_ids = kids.map { it.toByteArray().toByteString() },
            algorithm = WidevinePsshData.Algorithm.AESCTR
        )

        if (_version == 1) _keyIds = kids
        _content = widevine.encode()
        _systemId = PsshBox.WIDEVINE
    }

    /**
     * Convert a Widevine PSSH to a PlayReady v4.3.0.0 PSSH.
     * Optional LA_URL/LUI_URL/DS_ID/DECRYPTORSETUP/CUSTOMDATA fields can be provided.
     */
    fun toPlayready(
        laUrl: String? = null,
        luiUrl: String? = null,
        dsId: ByteArray? = null,
        decryptorSetup: String? = null,
        customData: String? = null
    ) {
        if (_systemId.contentEquals(PsshBox.PLAYREADY_SYSTEM_ID)) throw ValueException("This is already a PlayReady PSSH")

        val keyIdsXml = keyIds().joinToString("") { kid ->
            val b64 = Base64.encode(kid.toByteArray())
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
                ${laUrl?.let { "<LA_URL>$it</LA_URL>" } ?: ""}
                ${luiUrl?.let { "<LUI_URL>$it</LUI_URL>" } ?: ""}
                ${dsId?.let { "<DS_ID>${Base64.encode(it)}</DS_ID>" } ?: ""}
                ${decryptorSetup?.let { "<DECRYPTORSETUP>$it</DECRYPTORSETUP>" } ?: ""}
                ${customData?.let { "<CUSTOMATTRIBUTES xmlns=\"\">$it</CUSTOMATTRIBUTES>" } ?: ""}
            </DATA>
        </WRMHEADER>
        """.trimIndent().encodeToUtf16LE()

        val body = ByteArrayOutputStream().apply {
            write(1.toLEU16())              // record count
            write(0x01.toLEU16())           // type: PlayReadyHeader
            write(prrValue.size.toLEU16())  // length
            write(prrValue)
        }.toByteArray()

        val pro = ByteArrayOutputStream().apply {
            write((body.size + 4).toLEU32())  // total size including this length field
            write(body)
        }.toByteArray()

        _content = pro
        _systemId = PsshBox.PLAYREADY_SYSTEM_ID
    }

    /**
     * For Widevine PSSH only: overwrite Key IDs in both WV header and, if v1, box field too.
     */
    fun setKeyIds(keyIds: List<UUID>) {
        if (!_systemId.contentEquals(PsshBox.WIDEVINE))
            throw ValueException("Only Widevine PSSH Boxes are supported, not ${_systemId.toHexString()}")

        if (_version == 1 || _keyIds.isNotEmpty()) _keyIds = keyIds

        val cenc = if (_content.isEmpty()) WidevinePsshData() else WidevinePsshData.ADAPTER.decode(_content)
        val updated = cenc.copy(
            key_ids = keyIds.map { it.toByteArray().toByteString() }
        )
        _content = updated.encode()
    }

    /** Overload that accepts a mixed list of UUID | String(hex/base64) | ByteArray. */
    fun setKeyIdsAny(keyIds: List<Any>) = setKeyIds(parseKeyIds(keyIds))

    companion object {
        /**
         * Convert a list of UUID | String(hex/base64) | ByteArray to UUIDs.
         * @throws IllegalArgumentException if any item has an unsupported type
         */
        fun parseKeyIds(keyIds: List<Any>): List<UUID> {
            require(keyIds.all { it is UUID || it is String || it is ByteArray }) { "Some items of key_ids are not a UUID, String, or ByteArray." }
            return keyIds.map { item ->
                when (item) {
                    is UUID -> item
                    is String -> {
                        val isHex = item.all { it in ('0'..'9') || it in ('a'..'f') || it in ('A'..'F') }
                        val bytes = if (isHex) item.decodeHex().toByteArray() else Base64.decode(item)
                        bytes.toByteString().uuidFromByteString()
                    }
                    is ByteArray -> item.toByteString().uuidFromByteString()
                    else -> error("unreachable")
                }
            }
        }

        /**
         * Create a new PSSH object.
         * - For version 0, provide initData only.
         * - For version 1, provide either keyIds or initData.
         */
        fun new(
            systemId: UUID,
            keyIds: List<UUID>? = null,
            initData: Any? = null,
            version: Int = 0,
            flags: Int = 0
        ): PSSH {
            require(version in 0..1) { "Invalid version, must be either 0 or 1, not $version." }
            require(flags >= 0) { "Invalid flags, cannot be less than 0." }

            if (version == 0 && keyIds != null && initData != null)
                throw ValueException("Version 0 PSSH boxes must use only init_data, not init_data and key_ids.")
            if (version == 1 && keyIds == null && initData == null)
                throw ValueException("Version 1 PSSH boxes must use either init_data or key_ids but neither were provided")

            val contentBytes: ByteArray = when (initData) {
                null -> ByteArray(0)
                is WidevinePsshData -> initData.encode()
                is String -> {
                    val isHex = initData.all { it in ('0'..'9') || it in ('a'..'f') || it in ('A'..'F') }
                    if (isHex) initData.decodeHex().toByteArray() else Base64.decode(initData)
                }
                is ByteArray -> initData
                else -> throw ValueException("Expecting init_data to be WidevinePsshData, hex, base64, or bytes, not ${initData::class}")
            }

            val box = PsshBox().apply {
                this.version = version
                this.flags = flags
                this.systemId = systemId.toByteArray()
                this.content = contentBytes
                this.keyIds = emptyList()
            }

            val pssh = PSSH(box)
            if (keyIds != null) {
                pssh._version = version // reinforce in case
                pssh.setKeyIds(keyIds)
            }
            return pssh
        }
    }
}
