@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine.utils

import okio.ByteString
import okio.ByteString.Companion.toByteString
import kotlin.io.encoding.Base64
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** Encode this string as UTF-16LE, two bytes per code unit. */
public fun String.encodeToUtf16LE(): ByteArray {
    val out = ByteArray(length * 2)
    for (i in indices) {
        val c = this[i].code
        out[i * 2] = (c and 0xFF).toByte()
        out[i * 2 + 1] = ((c ushr 8) and 0xFF).toByte()
    }
    return out
}

/** Decode UTF-16LE bytes back to a string. A trailing odd byte is ignored. */
public fun ByteArray.decodeToStringUtf16LE(): String {
    val chars = CharArray(size / 2)
    for (i in chars.indices) {
        val lo = this[i * 2].toInt() and 0xFF
        val hi = this[i * 2 + 1].toInt() and 0xFF
        chars[i] = ((hi shl 8) or lo).toChar()
    }
    return chars.concatToString()
}

/** Interpret this [ByteString] as a hex-encoded [Uuid] string. */
public fun ByteString.uuidFromHexByteString(): Uuid = Uuid.parseHex(utf8())

public fun ByteArray.toUTF8(): String = decodeToString()

public fun ByteArray.toUUID(): Uuid {
    if (size != 16) throw ValueException("A UUID must be exactly 16 bytes, not $size")
    var most = 0L
    var least = 0L
    for (i in 0..7) most = (most shl 8) or (this[i].toLong() and 0xFF)
    for (i in 8..15) least = (least shl 8) or (this[i].toLong() and 0xFF)
    return Uuid.fromLongs(most, least)
}

/**
 * Interpret 16 bytes as a little-endian (Microsoft) GUID, as PlayReady stores Key IDs.
 *
 * The first three GUID components are byte-reversed relative to the big-endian form used
 * by `cenc:default_KID` and Widevine. The swap is its own inverse, so this also converts
 * back. Note pywidevine does **not** swap (`pssh.py:276`) and therefore reports PlayReady
 * KIDs that disagree with the manifest's own `cenc:default_KID`; the manifest is the
 * authority, so ktvine diverges here deliberately.
 */
public fun ByteArray.swapGuidEndianness(): ByteArray {
    if (size != 16) throw ValueException("A GUID must be exactly 16 bytes, not $size")
    val out = copyOf()
    out[0] = this[3]
    out[1] = this[2]
    out[2] = this[1]
    out[3] = this[0]
    out[4] = this[5]
    out[5] = this[4]
    out[6] = this[7]
    out[7] = this[6]
    return out
}

/** Read 16 little-endian GUID bytes as a [Uuid]. */
public fun ByteArray.uuidFromLittleEndian(): Uuid = swapGuidEndianness().toUUID()

/** Write this [Uuid] as 16 little-endian GUID bytes. */
public fun Uuid.toLittleEndianByteArray(): ByteArray = toByteArray().swapGuidEndianness()

/** Interpret this [ByteString] as a 16-byte [Uuid]. */
public fun ByteString.uuidFromByteString(): Uuid = this.toByteArray().toUUID()

/**
 * Interpret this [ByteString] as a big-endian unsigned number widened to a [Uuid].
 *
 * Used for KIDs that are neither 16 raw bytes nor 32 hex characters.
 */
public fun ByteString.uuidFromByteArray(): Uuid {
    var most = 0L
    var least = 0L
    // Only the low 16 bytes fit; anything beyond would overflow a UUID anyway.
    val bytes = toByteArray().let { if (it.size > 16) it.copyOfRange(it.size - 16, it.size) else it }
    for (b in bytes) {
        most = (most shl 8) or (least ushr 56)
        least = (least shl 8) or (b.toLong() and 0xFF)
    }
    return Uuid.fromLongs(most, least)
}

/** Convert this [Int] to little-endian unsigned 16-bit value [ByteArray]. */
public fun Int.toLEU16(): ByteArray = byteArrayOf(
    (this and 0xFF).toByte(),
    ((this ushr 8) and 0xFF).toByte(),
)

/** Convert this [Int] to little-endian unsigned 32-bit value [ByteArray]. */
public fun Int.toLEU32(): ByteArray = byteArrayOf(
    (this and 0xFF).toByte(),
    ((this ushr 8) and 0xFF).toByte(),
    ((this ushr 16) and 0xFF).toByte(),
    ((this ushr 24) and 0xFF).toByte(),
)

/** Convert a [ByteArray] to a lowercase hex string. */
public fun ByteArray.toHexString(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

/**
 * Convert a KID from a License `KeyContainer.id` to a [Uuid].
 *
 * KID bytes are not always 16 raw bytes: some services send a decimal digit string, and
 * some send fewer than 16 bytes. They are never Base64 — decoding them as such (as this
 * did) silently mangles every ASCII or hex-string KID. Use the [String] overload for
 * Base64 input.
 *
 * Returns the nil UUID for a missing or empty KID.
 */
public fun ByteString?.kidToUuid(): Uuid {
    var kidBytes = this?.toByteArray()
    if (kidBytes == null || kidBytes.isEmpty()) {
        return Uuid.NIL
    }

    val asText = kidBytes.toUTF8()
    if (asText.isNotEmpty() && asText.all { it.isDigit() }) {
        return decimalStringToUuid(asText)
    }

    if (kidBytes.size < 16) {
        kidBytes += ByteArray(16 - kidBytes.size)
    }

    return kidBytes.toByteString(0, 16).uuidFromByteString()
}

/**
 * Parse a decimal digit string into a [Uuid], matching pywidevine's `UUID(int=…)`.
 *
 * Done by hand across two `Long`s because there is no multiplatform big integer; values
 * above 2^128 wrap, exactly as truncating to 16 bytes would.
 */
private fun decimalStringToUuid(digits: String): Uuid {
    var most = 0L
    var least = 0L
    for (c in digits) {
        // value = value * 10 + digit, carrying from the low half into the high half.
        val lo = least and 0xFFFFFFFFL
        val hi = least ushr 32

        val loProduct = lo * 10L + (c - '0').toLong()
        val hiProduct = hi * 10L + (loProduct ushr 32)

        least = (hiProduct shl 32) or (loProduct and 0xFFFFFFFFL)
        most = most * 10L + (hiProduct ushr 32)
    }
    return Uuid.fromLongs(most, least)
}

/** Convert a Base64-encoded KID [String] to a [Uuid]. */
public fun String.kidToUuid(): Uuid = Base64.decode(this).toByteString().kidToUuid()

/** Escape the five XML predefined entities so interpolated text cannot break the document. */
public fun escapeXml(value: String): String = buildString(value.length) {
    for (c in value) {
        when (c) {
            '&' -> append("&amp;")
            '<' -> append("&lt;")
            '>' -> append("&gt;")
            '"' -> append("&quot;")
            '\'' -> append("&apos;")
            else -> append(c)
        }
    }
}

/** Reverse of [escapeXml] for the five predefined entities and numeric character references. */
public fun unescapeXml(value: String): String {
    if (!value.contains('&')) return value
    return Regex("&(#x?[0-9A-Fa-f]+|amp|lt|gt|quot|apos);").replace(value) { match ->
        when (val entity = match.groupValues[1]) {
            "amp" -> "&"
            "lt" -> "<"
            "gt" -> ">"
            "quot" -> "\""
            "apos" -> "'"
            else -> {
                val code = if (entity.startsWith("#x") || entity.startsWith("#X")) {
                    entity.drop(2).toIntOrNull(16)
                } else {
                    entity.drop(1).toIntOrNull()
                }
                code?.let { it.toChar().toString() } ?: match.value
            }
        }
    }
}

/** True when [needle] occurs anywhere in this array. */
public fun ByteArray.containsSubarray(needle: ByteArray): Boolean {
    if (needle.isEmpty()) return true
    if (needle.size > size) return false
    outer@ for (start in 0..(size - needle.size)) {
        for (i in needle.indices) {
            if (this[start + i] != needle[i]) continue@outer
        }
        return true
    }
    return false
}
