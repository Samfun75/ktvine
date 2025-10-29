package org.samfun.ktvine.core

import co.touchlab.kermit.Logger
import okio.Buffer
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.proto.WidevinePsshData
import org.samfun.ktvine.utils.*
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
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
    private var _systemId: ByteArray = WIDEVINE
    private var _content: ByteArray = ByteArray(0)

    /** Raw init data contained within the PSSH box. */
    val initData: ByteArray get() = _content

    /** Create from a Base64-encoded PSSH box or header bytes. */
    constructor(data: String) : this(Base64.decode(data))

    /** Create from raw bytes of a PSSH box or header bytes. */
    constructor(data: ByteArray) {
        val box = parseSinglePssh(data)
        this._systemId = box._systemId
        this._flags = box._flags
        this._version = box._version
        this._keyIds = box._keyIds
        this._content = box._content
    }

    constructor(systemId: ByteArray, version: Int, flags: Int, keyIds: List<UUID>, content: ByteArray) {
        _systemId = systemId
        _flags = flags
        _version = version
        _keyIds = keyIds
        _content = content
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

                        "4.1.0.0", "4.2.0.0", "4.3.0.0" -> Regex(
                            """<KID\b[^>]*\bVALUE=\"([^\"]+)\"""",
                            RegexOption.IGNORE_CASE
                        )
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

        throw ValueException("This PSSH is not supported by key_ids(), ${exportBase64()}")
    }


    override fun toString(): String = exportBase64()

    /** Convert PlayReady PSSH to a Widevine PSSH. */
    fun toWidevine() {
        if (_systemId.contentEquals(WIDEVINE)) throw ValueException("This is already a Widevine PSSH")

        val kids = keyIds()
        val widevine = WidevinePsshData(
            key_ids = kids.map { it.toByteArray().toByteString() },
            algorithm = WidevinePsshData.Algorithm.AESCTR
        )

        if (_version == 1) _keyIds = kids
        _content = widevine.encode()
        _systemId = WIDEVINE
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
        if (_systemId.contentEquals(PLAYREADY_SYSTEM_ID)) throw ValueException("This is already a PlayReady PSSH")

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
        _systemId = PLAYREADY_SYSTEM_ID
    }

    /**
     * For Widevine PSSH only: overwrite Key IDs in both WV header and, if v1, box field too.
     */
    fun setKeyIds(keyIds: List<UUID>) {
        if (!_systemId.contentEquals(WIDEVINE))
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


    /** Export the PSSH object as a full PSSH box in Base64 form. */
    fun exportBase64(): String {
        return Base64.encode(export())
    }

    /** Export the PSSH object as a full PSSH box in bytes form. */
    fun export(): ByteArray {
        // 1. Calculate the required buffer size
        val totalSize = calculatePsshSize()

        // 2. Allocate and set byte order
        val buffer = ByteBuffer.allocate(totalSize).order(ByteOrder.BIG_ENDIAN)

        // 3. ISOBMFF Box Header (Size + Type)
        buffer.putInt(totalSize)
        buffer.put("pssh".encodeUtf8().toByteArray())

        // 4. FullBox Header (Version + Flags)
        buffer.put(this._version.toByte())

        // Write the 24-bit flags
        buffer.put((this._flags shr 16).toByte())
        buffer.put((this._flags shr 8).toByte())
        buffer.put(this._flags.toByte())

        // 5. SystemID
        writeUuid(buffer, this._systemId.toUUID())

        // 6. Key IDs (Version 1 only)
        if (this._version == 1) {
            buffer.putInt(this._keyIds.size) // KeyIdCount
            this._keyIds.forEach { writeUuid(buffer, it) }
        }

        // 7. PSSH Data (Size + Data)
        buffer.putInt(this._content.size) // DataSize
        buffer.put(this._content)         // Data

        return buffer.array()
    }

    private fun parseSinglePssh(bytes: ByteArray): PSSH {
        Logger.d("ktvine") { "Attempting to parse data as full PSSH box: ${bytes.toHexString()}" }
        val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)

        while (buffer.remaining() >= 8) {
            val startPos = buffer.position()
            // Standard Box Header (Size + Type)
            val size = readUint32(buffer)
            val type = readFourCC(buffer)

            var boxSize = size.toLong()

            // 64-bit Size (BoxSize == 1)
            if (boxSize == 1L) {
                if (buffer.remaining() < 8) break
                boxSize = buffer.long
                // Last Box Extends to EOF (BoxSize == 0) - common for top-level file
            } else if (boxSize == 0L) {
                boxSize = (buffer.limit() - startPos).toLong()
            }

            if (boxSize < 8) break // Must have at least Size and Type

            val payloadSize = (boxSize - (buffer.position() - startPos)).toInt()

            if (type == "pssh") {
                Logger.d("ktvine") { "Found PSSH box Attempting to parse data" }
                if (buffer.remaining() < payloadSize) break
                val payload = ByteArray(payloadSize)
                buffer.get(payload)
                return parsePsshPayload(payload)
            } else {
                // Skip the payload of non-pssh box
                Logger.d("ktvine") { "No PSSH box found skipping" }
                val skip = payloadSize.coerceAtMost(buffer.remaining())
                buffer.position(buffer.position() + skip)
            }
        }

        throw InvalidBoxException("Could not find valid PSSH box in provided data.")
    }

    private fun parsePsshPayload(payload: ByteArray): PSSH {
        val b = ByteBuffer.wrap(payload).order(ByteOrder.BIG_ENDIAN)

        if (b.remaining() < 20) throw InvalidBoxException("PSSH payload too small to contain required fields.")

        val version = b.get().toInt() and 0xFF

        val flagsBytes = ByteArray(3)
        b.get(flagsBytes)
        val flags = (flagsBytes[0].toInt() and 0xFF shl 16) or
                (flagsBytes[1].toInt() and 0xFF shl 8) or
                (flagsBytes[2].toInt() and 0xFF)

        val systemId = readUuid(b)

        val keyIds = mutableListOf<UUID>()

        Logger.d("ktvine") { "PSSH box version: $version" }
        if (version > 1) throw InvalidBoxException("Unsupported PSSH version: $version")

        if (version == 1) {
            if (b.remaining() < 4) throw InvalidBoxException("PSSH payload too small to contain key ID count")

            val keyCount = readUint32(b).toInt()
            Logger.d("ktvine") { "PSSH box key count: $keyCount" }

            if (b.remaining() < keyCount * 16) throw InvalidBoxException("PSSH payload too small to contain $keyCount key IDs")

            repeat(keyCount) { keyIds.add(readUuid(b)) }
        }

        if (b.remaining() < 4) throw InvalidBoxException("PSSH payload too small to contain data size")
        val dataSize = readUint32(b).toInt()

        if (b.remaining() < dataSize) throw InvalidBoxException("PSSH payload too small to contain data")
        val data = ByteArray(dataSize)
        b.get(data)

        Logger.i("ktvine") { "Successfully parsed PSSH box data" }
        return PSSH(systemId.toByteArray(), version, flags, keyIds, data)
    }

    private fun calculatePsshSize(): Int {
        var size = 8 // Box header (Size + Type)
        size += 1 // Version
        size += 3 // Flags (24-bit)
        size += 16 // SystemID

        if (this._version == 1) {
            size += 4 // KeyIdCount
            size += this._keyIds.size * 16 // Key IDs (count * 16 bytes)
        }

        size += 4 // DataSize
        size += this._content.size // Data bytes

        return size
    }

    private fun readUint32(buffer: ByteBuffer): Long {
        return buffer.int.toLong() and 0xFFFFFFFFL
    }

    private fun readFourCC(buffer: ByteBuffer): String {
        val chars = ByteArray(4)
        buffer.get(chars)
        return chars.toUTF8()
    }

    private fun readUuid(buffer: ByteBuffer): UUID {
        val msb = buffer.long
        val lsb = buffer.long
        return UUID(msb, lsb)
    }

    private fun writeUuid(buffer: ByteBuffer, uuid: UUID) {
        buffer.putLong(uuid.mostSignificantBits)
        buffer.putLong(uuid.leastSignificantBits)
    }

    companion object {
        val WIDEVINE: ByteArray = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed").toByteArray()
        val PLAYREADY_SYSTEM_ID: ByteArray = UUID.fromString("9A04F079-9840-4286-AB92-E65BE0885F95").toByteArray()


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

            return PSSH(
                systemId = systemId.toByteArray(),
                version = version,
                flags = flags,
                keyIds = keyIds ?: emptyList(),
                content = contentBytes
            )
        }
    }
}
