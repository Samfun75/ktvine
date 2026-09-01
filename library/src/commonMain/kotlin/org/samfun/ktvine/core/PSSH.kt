@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine.core

import okio.Buffer
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.encodeUtf8
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.proto.WidevinePsshData
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.utils.InvalidBoxException
import org.samfun.ktvine.utils.KtvineLog
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.containsSubarray
import org.samfun.ktvine.utils.decodeToStringUtf16LE
import org.samfun.ktvine.utils.encodeToUtf16LE
import org.samfun.ktvine.utils.toHexString
import org.samfun.ktvine.utils.toUTF8
import org.samfun.ktvine.utils.toUUID
import org.samfun.ktvine.utils.uuidFromByteArray
import org.samfun.ktvine.utils.uuidFromByteString
import org.samfun.ktvine.utils.uuidFromHexByteString
import kotlin.io.encoding.Base64
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Helper for parsing and building PSSH (Protection System Specific Header) boxes.
 * Supports both Widevine and PlayReady headers and provides conversions.
 */
public class PSSH {

    private var _version: Int = 0
    private var _flags: Int = 0
    private var _keyIds: List<Uuid> = listOf()
    private var _systemId: ByteArray = WIDEVINE
    private var _content: ByteArray = ByteArray(0)

    /** Raw init data contained within the PSSH box. */
    public val initData: ByteArray get() = _content

    /**
     * Create from a Base64-encoded PSSH box, Widevine CENC header, or PlayReady header.
     * @see PSSH constructor taking [ByteArray] for how [strict] is applied.
     */
    public constructor(data: String, strict: Boolean = false) : this(decodeBase64OrThrow(data), strict)

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
    public constructor(data: ByteArray, strict: Boolean = false) {
        val box = interpret(data, strict)
        this._systemId = box._systemId
        this._flags = box._flags
        this._version = box._version
        this._keyIds = box._keyIds
        this._content = box._content
    }

    public constructor(systemId: ByteArray, version: Int, flags: Int, keyIds: List<Uuid>, content: ByteArray) {
        _systemId = systemId
        _flags = flags
        _version = version
        _keyIds = keyIds
        _content = content
    }

    /**
     * Encryption scheme this header declares, e.g. `AESCTR` or `AESCBC`, or `null` when the
     * header does not say.
     *
     * PlayReady spells it `ALGID` — document-level under `<PROTECTINFO>` in v4.0.0.0, and
     * per-KID from v4.2.0.0 on. Widevine spells it `protection_scheme`, a 4CC packed into a
     * uint32. It used to be dropped on conversion and replaced with a hardcoded AESCTR.
     */
    public val encryptionScheme: String?
        get() = when {
            _systemId.contentEquals(PLAYREADY_SYSTEM_ID) -> playreadyAlgid()
            else -> runCatching { widevineScheme() }.getOrNull()
        }

    private fun playreadyAlgid(): String? =
        runCatching { PlayreadyHeader.parse(playreadyHeaderXml()) }.getOrNull()?.algid

    // `algorithm` is deprecated in the schema but still the only signal some packagers emit.
    @Suppress("DEPRECATION")
    private fun widevineScheme(): String? {
        val header = WidevinePsshData.ADAPTER.decode(_content)
        header.protection_scheme?.let { return fourCcToScheme(it) }
        return when (header.algorithm) {
            WidevinePsshData.Algorithm.AESCTR -> "AESCTR"
            WidevinePsshData.Algorithm.UNENCRYPTED -> "UNENCRYPTED"
            null -> null
        }
    }

    /**
     * Crypto period this header names, for content using key rotation, or `null`.
     *
     * Widevine only; a PlayReady header has no equivalent.
     */
    public val cryptoPeriodIndex: Int?
        get() = widevineHeaderOrNull()?.crypto_period_index

    /** Duration of each crypto period in seconds, for content using key rotation, or `null`. */
    public val cryptoPeriodSeconds: Int?
        get() = widevineHeaderOrNull()?.crypto_period_seconds

    private fun widevineHeaderOrNull(): WidevinePsshData? {
        if (_systemId.contentEquals(PLAYREADY_SYSTEM_ID)) return null
        return runCatching { WidevinePsshData.ADAPTER.decode(_content) }.getOrNull()
    }

    /**
     * Point this PSSH at a specific crypto period.
     *
     * With key rotation the licence for each period is requested with the same init data
     * but a different `crypto_period_index`, so rotating is: set the index, build a fresh
     * challenge, parse the response.
     *
     * @throws ValueException for a non-Widevine box, which has no such field
     */
    public fun setCryptoPeriodIndex(index: Int) {
        if (!_systemId.contentEquals(WIDEVINE)) {
            throw ValueException("Only Widevine PSSH Boxes carry a crypto period, not ${_systemId.toHexString()}")
        }
        if (index < 0) throw ValueException("Invalid crypto period index $index, cannot be negative.")

        val header = if (_content.isEmpty()) {
            WidevinePsshData()
        } else {
            try {
                WidevinePsshData.ADAPTER.decode(_content)
            } catch (e: Throwable) {
                throw DecodeException("Could not parse init data as a WidevineCencHeader, $e")
            }
        }
        _content = header.copy(crypto_period_index = index).encode()
    }

    /**
     * Get all Key IDs from within the Box or Init Data, wherever possible.
     *
     * Supports:
     * - Version 1 PSSH Boxes
     * - WidevineCencHeaders
     * - PlayReadyHeaders (4.0.0.0->4.3.0.0)
     */
    public fun keyIds(): List<Uuid> {
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

    private fun widevineKeyIds(): List<Uuid> {
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

    /** The record-type 0x01 PlayReady header of this box's PRO, as text. */
    private fun playreadyHeaderXml(): String {
        val proData = Buffer().write(_content)
        val size = try {
            proData.readIntLe()
        } catch (e: Throwable) {
            throw DecodeException("The PlayReadyObject seems to be corrupt, $e")
        }
        if (size != _content.size) {
            throw ValueException("The PlayReadyObject seems to be corrupt (declares $size bytes, has ${_content.size})")
        }

        val proRecordCount = proData.readShortLe().toInt() and 0xFFFF
        repeat(proRecordCount) {
            val prrType = proData.readShortLe().toInt() and 0xFFFF
            val prrLength = proData.readShortLe().toInt() and 0xFFFF
            val prrValue = proData.readByteArray(prrLength.toLong())
            // Type 0x03 is the Embedded License Store, which this library does not handle.
            if (prrType != 0x01) return@repeat
            return prrValue.decodeToStringUtf16LE()
        }

        throw ValueException("no PlayReadyHeader within the object")
    }

    private fun playreadyKeyIds(): List<Uuid> = PlayreadyHeader.parse(playreadyHeaderXml()).keyIds

    override fun toString(): String = exportBase64()

    /** Convert PlayReady PSSH to a Widevine PSSH. */
    public fun toWidevine() {
        if (_systemId.contentEquals(WIDEVINE)) throw ValueException("This is already a Widevine PSSH")

        val kids = keyIds()

        val scheme = encryptionScheme
        val widevine = WidevinePsshData(
            key_ids = kids.map { it.toByteArray().toByteString() },
            // The deprecated `algorithm` enum only knows AESCTR, so anything else is carried
            // by `protection_scheme` alone.
            algorithm = if (scheme == null || scheme.equals("AESCTR", ignoreCase = true)) {
                WidevinePsshData.Algorithm.AESCTR
            } else {
                null
            },
            protection_scheme = schemeToFourCc(scheme),
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
    public fun toPlayready(
        laUrl: String? = null,
        luiUrl: String? = null,
        dsId: ByteArray? = null,
        decryptorSetup: String? = null,
        customData: String? = null,
    ) {
        if (_systemId.contentEquals(PLAYREADY_SYSTEM_ID)) throw ValueException("This is already a PlayReady PSSH")

        _content = buildPlayreadyPro(
            keyIds = keyIds(),
            algid = encryptionScheme ?: "AESCTR",
            laUrl = laUrl,
            luiUrl = luiUrl,
            dsId = dsId,
            decryptorSetup = decryptorSetup,
            customData = customData,
        )
        _systemId = PLAYREADY_SYSTEM_ID
    }

    /**
     * Overwrite the Key IDs of this box.
     *
     * For Widevine this rewrites the CENC header (and the v1 box field). For PlayReady the
     * PRO is rebuilt as a v4.3.0.0 header, carrying over the encryption scheme and the
     * optional LA_URL / LUI_URL / DS_ID / DECRYPTORSETUP / CUSTOMATTRIBUTES elements.
     *
     * @throws ValueException for any other system id
     */
    public fun setKeyIds(keyIds: List<Uuid>) {
        when {
            _systemId.contentEquals(WIDEVINE) -> {
                if (_version == 1 || _keyIds.isNotEmpty()) _keyIds = keyIds

                val cenc = if (_content.isEmpty()) WidevinePsshData() else WidevinePsshData.ADAPTER.decode(_content)
                _content = cenc.copy(key_ids = keyIds.map { it.toByteArray().toByteString() }).encode()
            }

            _systemId.contentEquals(PLAYREADY_SYSTEM_ID) -> {
                if (_version == 1 || _keyIds.isNotEmpty()) _keyIds = keyIds

                val existing = runCatching { PlayreadyHeader.parse(playreadyHeaderXml()) }.getOrNull()
                _content = buildPlayreadyPro(
                    keyIds = keyIds,
                    algid = existing?.algid ?: "AESCTR",
                    laUrl = existing?.laUrl,
                    luiUrl = existing?.luiUrl,
                    dsId = existing?.dsId,
                    decryptorSetup = existing?.decryptorSetup,
                    customData = existing?.customAttributes,
                )
            }

            else -> throw ValueException(
                "Only Widevine and PlayReady PSSH Boxes are supported, not ${_systemId.toHexString()}",
            )
        }
    }

    /** Overload that accepts a mixed list of UUID | String(hex/base64) | ByteArray. */
    public fun setKeyIdsAny(keyIds: List<Any>): Unit = setKeyIds(parseKeyIds(keyIds))

    /** Export the PSSH object as a full PSSH box in Base64 form. */
    public fun exportBase64(): String {
        return Base64.encode(export())
    }

    /** Export the PSSH object as a full PSSH box in bytes form. */
    public fun export(): ByteArray {
        val buffer = Buffer()

        // ISOBMFF Box Header (Size + Type). okio writes big-endian by default.
        buffer.writeInt(calculatePsshSize())
        buffer.write("pssh".encodeUtf8())

        // FullBox Header (Version + 24-bit Flags)
        buffer.writeByte(this._version)
        buffer.writeByte(this._flags shr 16)
        buffer.writeByte(this._flags shr 8)
        buffer.writeByte(this._flags)

        buffer.write(this._systemId)

        // Key IDs (Version 1 only)
        if (this._version == 1) {
            buffer.writeInt(this._keyIds.size)
            this._keyIds.forEach { buffer.write(it.toByteArray()) }
        }

        buffer.writeInt(this._content.size)
        buffer.write(this._content)

        return buffer.readByteArray()
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

    public companion object {

        // WidevinePsshData.protection_scheme packs a 4CC into a uint32; see the proto.
        private const val FOURCC_CENC = 0x63656E63 // 'cenc', AES-CTR
        private const val FOURCC_CBC1 = 0x63626331 // 'cbc1', AES-CBC
        private const val FOURCC_CENS = 0x63656E73 // 'cens', AES-CTR pattern encryption
        private const val FOURCC_CBCS = 0x63626373 // 'cbcs', AES-CBC pattern encryption

        private fun fourCcToScheme(fourCc: Int): String? = when (fourCc) {
            FOURCC_CENC -> "AESCTR"
            FOURCC_CBC1 -> "AESCBC"
            FOURCC_CENS -> "AESCTRPATTERN"
            FOURCC_CBCS -> "AESCBCPATTERN"
            else -> null
        }

        private fun schemeToFourCc(scheme: String?): Int? = when (scheme?.uppercase()) {
            "AESCTR" -> FOURCC_CENC
            "AESCBC" -> FOURCC_CBC1
            "AESCTRPATTERN" -> FOURCC_CENS
            "AESCBCPATTERN" -> FOURCC_CBCS
            else -> null
        }

        /**
         * Build a PlayReady Object wrapping a single v4.3.0.0 header record.
         *
         * [laUrl], [luiUrl] and [decryptorSetup] are XML-escaped. [customData] is not — the
         * spec has the content author supply raw XML there.
         *
         * @throws ValueException if the header exceeds the u16 record length limit
         */
        private fun buildPlayreadyPro(
            keyIds: List<Uuid>,
            algid: String,
            laUrl: String? = null,
            luiUrl: String? = null,
            dsId: ByteArray? = null,
            decryptorSetup: String? = null,
            customData: String? = null,
        ): ByteArray {
            val prrValue = PlayreadyHeader.build(
                keyIds = keyIds,
                algid = algid,
                laUrl = laUrl,
                luiUrl = luiUrl,
                dsId = dsId,
                decryptorSetup = decryptorSetup,
                customAttributes = customData,
            ).encodeToUtf16LE()

            // The record length field is a u16; toLEU16 would silently truncate past 65535.
            if (prrValue.size > 0xFFFF) {
                throw ValueException(
                    "PlayReadyHeader is ${prrValue.size} bytes, over the 65535-byte record limit",
                )
            }

            val body = Buffer().apply {
                writeShortLe(1) // record count
                writeShortLe(0x01) // type: PlayReadyHeader
                writeShortLe(prrValue.size) // length
                write(prrValue)
            }.readByteArray()

            return Buffer().apply {
                writeIntLe(body.size + 4) // total size including this length field
                write(body)
            }.readByteArray()
        }

        private val WRMHEADER_CLOSE_TAG = "</WRMHEADER>".encodeToUtf16LE()

        private fun decodeBase64OrThrow(data: String): ByteArray = try {
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
                    "Could not parse data as a PSSH box, a WidevineCencHeader, or a PlayReadyHeader.",
                )
            }

            // Some license servers accept custom init data (Netflix MSL, for one).
            KtvineLog.d { "Unrecognised init data, wrapping it in a v0 Widevine box" }
            return PSSH(WIDEVINE, 0, 0, emptyList(), data)
        }

        /**
         * Parse every `pssh` box in an ISOBMFF byte sequence.
         *
         * Multi-DRM init segments carry Widevine and PlayReady boxes side by side; the
         * [PSSH] constructors only ever return the first.
         */
        public fun parseAll(data: ByteArray): List<PSSH> = parseBoxes(data)

        /** Parse [data] as Base64 and return every `pssh` box in it. */
        public fun parseAll(data: String): List<PSSH> = parseBoxes(decodeBase64OrThrow(data))

        /**
         * Pick the `pssh` box for one DRM system out of an init segment.
         * @return the first matching box, or `null` when the segment carries none.
         */
        public fun fromInitSegment(data: ByteArray, systemId: ByteArray = WIDEVINE): PSSH? =
            parseBoxes(data).firstOrNull { it._systemId.contentEquals(systemId) }

        /** Walk an ISOBMFF box sequence and return every `pssh` box found, in order. */
        private fun parseBoxes(bytes: ByteArray): List<PSSH> {
            // Verbose only: this dumps the whole init data, which callers may consider sensitive.
            KtvineLog.v { "Parsing ${bytes.size} bytes as an ISOBMFF box sequence: ${bytes.toHexString()}" }
            val buffer = Buffer().write(bytes)
            val total = bytes.size
            val found = mutableListOf<PSSH>()

            while (buffer.size >= 8) {
                val startPos = total - buffer.size
                val size = buffer.readInt().toLong() and 0xFFFFFFFFL
                val type = buffer.readByteArray(4).toUTF8()
                var headerSize = 8L

                var boxSize = size
                if (boxSize == 1L) {
                    // 64-bit size
                    if (buffer.size < 8) break
                    boxSize = buffer.readLong()
                    headerSize = 16L
                } else if (boxSize == 0L) {
                    // Last box extends to EOF
                    boxSize = (total - startPos).toLong()
                }

                if (boxSize < headerSize) break

                val payloadSize = boxSize - headerSize
                if (payloadSize < 0 || buffer.size < payloadSize) break

                if (type == "pssh") {
                    found.add(parsePsshPayload(buffer.readByteArray(payloadSize)))
                } else {
                    buffer.skip(payloadSize)
                }
            }

            return found
        }

        private fun parsePsshPayload(payload: ByteArray): PSSH {
            val b = Buffer().write(payload)

            if (b.size < 20) throw InvalidBoxException("PSSH payload too small to contain required fields.")

            val version = b.readByte().toInt() and 0xFF

            val flags = ((b.readByte().toInt() and 0xFF) shl 16) or
                ((b.readByte().toInt() and 0xFF) shl 8) or
                (b.readByte().toInt() and 0xFF)

            val systemId = b.readByteArray(16)

            val keyIds = mutableListOf<Uuid>()

            KtvineLog.v { "PSSH box version: $version" }
            if (version > 1) throw InvalidBoxException("Unsupported PSSH version: $version")

            if (version == 1) {
                if (b.size < 4) throw InvalidBoxException("PSSH payload too small to contain key ID count")

                val keyCount = b.readInt().toLong() and 0xFFFFFFFFL
                KtvineLog.v { "PSSH box key count: $keyCount" }

                if (b.size < keyCount * 16) {
                    throw InvalidBoxException(
                        "PSSH payload too small to contain $keyCount key IDs",
                    )
                }

                repeat(keyCount.toInt()) { keyIds.add(b.readByteArray(16).toUUID()) }
            }

            if (b.size < 4) throw InvalidBoxException("PSSH payload too small to contain data size")
            val dataSize = b.readInt().toLong() and 0xFFFFFFFFL

            if (b.size < dataSize) throw InvalidBoxException("PSSH payload too small to contain data")
            val data = b.readByteArray(dataSize)

            KtvineLog.v { "Successfully parsed PSSH box data" }
            return PSSH(systemId, version, flags, keyIds, data)
        }

        public val WIDEVINE: ByteArray = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed").toByteArray()
        public val PLAYREADY_SYSTEM_ID: ByteArray = Uuid.parse("9A04F079-9840-4286-AB92-E65BE0885F95").toByteArray()

        /**
         * Convert a list of UUID | String(hex/base64) | ByteArray to UUIDs.
         * @throws ValueException if any item has an unsupported type
         */
        public fun parseKeyIds(keyIds: List<Any>): List<Uuid> {
            if (!keyIds.all { it is Uuid || it is String || it is ByteArray }) {
                throw ValueException("Some items of key_ids are not a UUID, String, or ByteArray.")
            }
            return keyIds.map { item ->
                when (item) {
                    is Uuid -> item
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
        public fun new(
            systemId: Uuid,
            keyIds: List<Uuid>? = null,
            initData: Any? = null,
            version: Int = 0,
            flags: Int = 0,
        ): PSSH {
            if (version !in 0..1) throw ValueException("Invalid version, must be either 0 or 1, not $version.")
            if (flags < 0) throw ValueException("Invalid flags, cannot be less than 0.")

            if (version == 0 && keyIds != null && initData != null) {
                throw ValueException("Version 0 PSSH boxes must use only init_data, not init_data and key_ids.")
            }
            if (version == 1 && keyIds == null && initData == null) {
                throw ValueException(
                    "Version 1 PSSH boxes must use either init_data or key_ids but neither were provided",
                )
            }

            val contentBytes: ByteArray = when (initData) {
                null -> ByteArray(0)
                is WidevinePsshData -> initData.encode()
                is String -> {
                    val isHex = initData.all { it in ('0'..'9') || it in ('a'..'f') || it in ('A'..'F') }
                    if (isHex) initData.decodeHex().toByteArray() else Base64.decode(initData)
                }

                is ByteArray -> initData
                else -> throw ValueException(
                    "Expecting init_data to be WidevinePsshData, hex, base64, or bytes, not ${initData::class}",
                )
            }

            val systemIdBytes = systemId.toByteArray()

            // Key ids alone used to leave _content empty, producing a box no client accepts.
            val content = when {
                contentBytes.isNotEmpty() || keyIds.isNullOrEmpty() -> contentBytes
                systemIdBytes.contentEquals(PLAYREADY_SYSTEM_ID) ->
                    buildPlayreadyPro(keyIds = keyIds, algid = "AESCTR")
                systemIdBytes.contentEquals(WIDEVINE) ->
                    WidevinePsshData(key_ids = keyIds.map { it.toByteArray().toByteString() }).encode()
                else -> contentBytes
            }

            return PSSH(
                systemId = systemIdBytes,
                version = version,
                flags = flags,
                keyIds = keyIds ?: emptyList(),
                content = content,
            )
        }
    }
}
