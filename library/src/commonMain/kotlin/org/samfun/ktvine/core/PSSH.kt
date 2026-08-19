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

    /**
     * Create from a Base64-encoded PSSH box, Widevine CENC header, or PlayReady header.
     * @see PSSH constructor taking [ByteArray] for how [strict] is applied.
     */
    constructor(data: String, strict: Boolean = false) : this(decodeBase64OrThrow(data), strict)

    /**
     * Create from raw bytes of a PSSH box, Widevine CENC header, or PlayReady header.
     *
     * The input is interpreted in this order:
     * 1. an ISOBMFF box sequence containing a `pssh` box;
     * 2. a bare `WidevinePsshData` CENC header — accepted only if re-encoding it reproduces
     *    the input exactly, since protobuf will happily "parse" many non-protobuf blobs;
     * 3. a bare PlayReady header or PlayReady Object, detected by a UTF-16LE
     *    `</WRMHEADER>`;
     * 4. anything else, in lenient mode, is wrapped verbatim as the `init_data` of a v0
     *    Widevine box. Some services take custom init data (Netflix MSL, for one).
     *
     * @param strict reject step 4 with a [DecodeException] instead of wrapping.
     */
    constructor(data: ByteArray, strict: Boolean = false) {
        val box = interpret(data, strict)
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

        // Dispatch on system_id rather than guessing. Whether a PRO happens to fail
        // protobuf decoding depends on whether its leading little-endian size byte forms
        // an invalid tag, so try-Widevine-first only worked by luck.
        if (_systemId.contentEquals(PLAYREADY_SYSTEM_ID)) return playreadyKeyIds()
        if (_systemId.contentEquals(WIDEVINE)) return widevineKeyIds()

        // Unknown system id: the box may still carry either header, so try both.
        return runCatching { widevineKeyIds() }.getOrNull()
            ?: runCatching { playreadyKeyIds() }.getOrNull()
            ?: throw ValueException("This PSSH is not supported by key_ids(), ${exportBase64()}")
    }

    private fun widevineKeyIds(): List<UUID> {
        val header = try {
            WidevinePsshData.ADAPTER.decode(_content)
        } catch (e: Throwable) {
            throw DecodeException("Could not parse init data as a WidevineCencHeader, $e")
        }
        return header.key_ids.map {
            when (it.size) {
                16 -> it.uuidFromByteString()
                32 -> it.uuidFromHexByteString() // stored as hex
                else -> it.uuidFromByteArray() // assuming stored as number
            }
        }
    }

    private fun playreadyKeyIds(): List<UUID> {
        val proData = Buffer().write(_content)
        val size = try {
            proData.readIntLe()
        } catch (e: Throwable) {
            throw DecodeException("The PlayReadyObject seems to be corrupt, $e")
        }
        if (size != _content.size)
            throw ValueException("The PlayReadyObject seems to be corrupt (declares $size bytes, has ${_content.size})")

        val proRecordCount = proData.readShortLe().toInt() and 0xFFFF
        repeat(proRecordCount) {
            val prrType = proData.readShortLe().toInt() and 0xFFFF
            val prrLength = proData.readShortLe().toInt() and 0xFFFF
            val prrValue = proData.readByteArray(prrLength.toLong())
            // Type 0x03 is the Embedded License Store, which this library does not handle.
            if (prrType != 0x01) return@repeat

            val xml = prrValue.decodeToStringUtf16LE()
            // Anchored to the element: an unanchored `version="..."` matches the
            // `<?xml version="1.0"?>` declaration many packagers emit.
            val version = Regex("""<WRMHEADER\b[^>]*\bversion=\"([^\"]+)\"""", RegexOption.IGNORE_CASE)
                .find(xml)?.groupValues?.get(1)
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

            return keyIdsB64.map { b64 -> Base64.decode(b64).uuidFromLittleEndian() }
        }

        throw ValueException("no PlayReadyHeader within the object")
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
     *
     * [laUrl], [luiUrl] and [decryptorSetup] are XML-escaped. [customData] is **not** —
     * the spec has the content author supply raw XML there, so it must already be valid.
     *
     * @throws ValueException if the resulting header exceeds the 65535-byte record limit
     */
    fun toPlayready(
        laUrl: String? = null,
        luiUrl: String? = null,
        dsId: ByteArray? = null,
        decryptorSetup: String? = null,
        customData: String? = null
    ) {
        if (_systemId.contentEquals(PLAYREADY_SYSTEM_ID)) throw ValueException("This is already a PlayReady PSSH")

        val prrValue = buildString {
            append("<WRMHEADER xmlns=\"http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader\" version=\"4.3.0.0\">")
            append("<DATA>")
            append("<PROTECTINFO><KIDS>")
            keyIds().forEach { kid ->
                append("<KID ALGID=\"AESCTR\" VALUE=\"${Base64.encode(kid.toLittleEndianByteArray())}\"></KID>")
            }
            append("</KIDS></PROTECTINFO>")
            laUrl?.let { append("<LA_URL>${escapeXml(it)}</LA_URL>") }
            luiUrl?.let { append("<LUI_URL>${escapeXml(it)}</LUI_URL>") }
            dsId?.let { append("<DS_ID>${Base64.encode(it)}</DS_ID>") }
            decryptorSetup?.let { append("<DECRYPTORSETUP>${escapeXml(it)}</DECRYPTORSETUP>") }
            customData?.let { append("<CUSTOMATTRIBUTES xmlns=\"\">$it</CUSTOMATTRIBUTES>") }
            append("</DATA>")
            append("</WRMHEADER>")
        }.encodeToUtf16LE()

        // The record length field is a u16; toLEU16 would silently truncate past 65535.
        if (prrValue.size > 0xFFFF)
            throw ValueException("PlayReadyHeader is ${prrValue.size} bytes, over the 65535-byte record limit")

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

    private fun writeUuid(buffer: ByteBuffer, uuid: UUID) {
        buffer.putLong(uuid.mostSignificantBits)
        buffer.putLong(uuid.leastSignificantBits)
    }

    companion object {

        private val WRMHEADER_CLOSE_TAG = "</WRMHEADER>".encodeToUtf16LE()

        private fun decodeBase64OrThrow(data: String): ByteArray =
            try {
                Base64.decode(data)
            } catch (e: Throwable) {
                throw DecodeException("Could not decode data as Base64, $e")
            }

        /** Apply the input cascade documented on the [PSSH] `ByteArray` constructor. */
        private fun interpret(data: ByteArray, strict: Boolean): PSSH {
            if (data.isEmpty()) throw ValueException("Data must not be empty.")

            parseBoxes(data).firstOrNull()?.let { return it }

            // A bare WidevinePsshData CENC header. Protobuf accepts a lot of junk, so only
            // trust the parse when re-encoding round-trips exactly.
            val cencHeader = runCatching { WidevinePsshData.ADAPTER.decode(data) }.getOrNull()
            if (cencHeader != null && cencHeader.encode().contentEquals(data)) {
                return PSSH(WIDEVINE, 0, 0, emptyList(), data)
            }

            // A bare PlayReady header or PlayReady Object. Stored as-is; keyIds() parses it.
            if (data.containsSubarray(WRMHEADER_CLOSE_TAG)) {
                return PSSH(PLAYREADY_SYSTEM_ID, 0, 0, emptyList(), data)
            }

            if (strict) {
                throw DecodeException(
                    "Could not parse data as a PSSH box, a WidevineCencHeader, or a PlayReadyHeader."
                )
            }

            // Some license servers accept custom init data (Netflix MSL, for one).
            Logger.d("ktvine") { "Unrecognised init data, wrapping it in a v0 Widevine box" }
            return PSSH(WIDEVINE, 0, 0, emptyList(), data)
        }

        /**
         * Parse every `pssh` box in an ISOBMFF byte sequence.
         *
         * Multi-DRM init segments carry Widevine and PlayReady boxes side by side; the
         * [PSSH] constructors only ever return the first.
         */
        fun parseAll(data: ByteArray): List<PSSH> = parseBoxes(data)

        /** Parse [data] as Base64 and return every `pssh` box in it. */
        fun parseAll(data: String): List<PSSH> = parseBoxes(decodeBase64OrThrow(data))

        /**
         * Pick the `pssh` box for one DRM system out of an init segment.
         * @return the first matching box, or `null` when the segment carries none.
         */
        fun fromInitSegment(data: ByteArray, systemId: ByteArray = WIDEVINE): PSSH? =
            parseBoxes(data).firstOrNull { it._systemId.contentEquals(systemId) }

        /** Walk an ISOBMFF box sequence and return every `pssh` box found, in order. */
        private fun parseBoxes(bytes: ByteArray): List<PSSH> {
            Logger.d("ktvine") { "Attempting to parse data as an ISOBMFF box sequence" }
            val buffer = ByteBuffer.wrap(bytes).order(ByteOrder.BIG_ENDIAN)
            val found = mutableListOf<PSSH>()

            while (buffer.remaining() >= 8) {
                val startPos = buffer.position()
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
                if (payloadSize < 0 || buffer.remaining() < payloadSize) break

                if (type == "pssh") {
                    val payload = ByteArray(payloadSize)
                    buffer.get(payload)
                    found.add(parsePsshPayload(payload))
                } else {
                    buffer.position(buffer.position() + payloadSize)
                }
            }

            return found
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
        val WIDEVINE: ByteArray = UUID.fromString("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed").toByteArray()
        val PLAYREADY_SYSTEM_ID: ByteArray = UUID.fromString("9A04F079-9840-4286-AB92-E65BE0885F95").toByteArray()


        /**
         * Convert a list of UUID | String(hex/base64) | ByteArray to UUIDs.
         * @throws ValueException if any item has an unsupported type
         */
        fun parseKeyIds(keyIds: List<Any>): List<UUID> {
            if (!keyIds.all { it is UUID || it is String || it is ByteArray })
                throw ValueException("Some items of key_ids are not a UUID, String, or ByteArray.")
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
            if (version !in 0..1) throw ValueException("Invalid version, must be either 0 or 1, not $version.")
            if (flags < 0) throw ValueException("Invalid flags, cannot be less than 0.")

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
