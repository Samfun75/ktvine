package org.samfun.ktvine.utils

import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import kotlin.io.encoding.Base64

/** Decode [String] to utf 16LE [ByteArray]. */
expect fun String.encodeToUtf16LE(): ByteArray

/** Decode [ByteArray] to string from utf 16LE. */
expect fun ByteArray.decodeToStringUtf16LE(): String

/** Interpret this [ByteString] as a hex-encoded [UUID] string. */
expect fun ByteString.uuidFromHexByteString(): UUID

expect fun ByteArray.toUTF8(): String

/** Convert a [UUID] to raw 16-byte array (big-endian). */
fun UUID.toByteArray(): ByteArray {
    val msb: Long = this.mostSignificantBits
    val lsb: Long = this.leastSignificantBits
    val buffer = ByteArray(16)

    for (i in 0..7) {
        buffer[i] = (msb ushr 8 * (7 - i)).toByte()
    }
    for (i in 8..15) {
        buffer[i] = (lsb ushr 8 * (7 - i)).toByte()
    }

    return buffer
}

fun ByteArray.toUUID(): UUID {
    val b = ByteBuffer.wrap(this)
    b.order(ByteOrder.BIG_ENDIAN)
    return UUID(b.getLong(), b.getLong())
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
fun ByteArray.swapGuidEndianness(): ByteArray {
    if (size != 16) throw ValueException("A GUID must be exactly 16 bytes, not $size")
    val out = copyOf()
    out[0] = this[3]; out[1] = this[2]; out[2] = this[1]; out[3] = this[0]
    out[4] = this[5]; out[5] = this[4]
    out[6] = this[7]; out[7] = this[6]
    return out
}

/** Read 16 little-endian GUID bytes as a [UUID]. */
fun ByteArray.uuidFromLittleEndian(): UUID = swapGuidEndianness().toUUID()

/** Write this [UUID] as 16 little-endian GUID bytes. */
fun UUID.toLittleEndianByteArray(): ByteArray = toByteArray().swapGuidEndianness()

/** Interpret this [ByteString] as a 16-byte [UUID]. */
fun ByteString.uuidFromByteString(): UUID = this.toByteArray().toUUID()

/** Interpret this [ByteString] as a big integer numeric [UUID] representation. */
fun ByteString.uuidFromByteArray(): UUID {
    val bigInt = BigInteger(1, this.toByteArray())
    val (mostSigBits, leastSigBits) = with(bigInt) {
        val most = shiftRight(64).toLong()
        val least = and(BigInteger("FFFFFFFFFFFFFFFF", 16)).toLong()
        most to least
    }
    return UUID(mostSigBits, leastSigBits)
}

/** Convert this [Int] to little-endian unsigned 16-bit value [ByteArray]. */
fun Int.toLEU16(): ByteArray = byteArrayOf(
    (this and 0xFF).toByte(),
    ((this ushr 8) and 0xFF).toByte(),
)

/** Convert this [Int] to little-endian unsigned 32-bit value [ByteArray]. */
fun Int.toLEU32(): ByteArray = byteArrayOf(
    (this and 0xFF).toByte(),
    ((this ushr 8) and 0xFF).toByte(),
    ((this ushr 16) and 0xFF).toByte(),
    ((this ushr 24) and 0xFF).toByte()
)

/** Convert a [ByteArray] to a lowercase hex string. */
fun ByteArray.toHexString(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

/**
 * Convert a KID from a License `KeyContainer.id` to a [UUID].
 *
 * KID bytes are not always 16 raw bytes: some services send a decimal digit string, and
 * some send fewer than 16 bytes. They are never Base64 — decoding them as such (as this
 * did) silently mangles every ASCII or hex-string KID. Use the [String] overload for
 * Base64 input.
 *
 * Returns `UUID(0, 0)` for a missing or empty KID.
 */
fun ByteString?.kidToUuid(): UUID {
    var kidBytes = this?.toByteArray()
    if (kidBytes == null || kidBytes.isEmpty()) {
        return UUID(0, 0)
    }

    val asText = kidBytes.toUTF8()
    if (asText.isNotEmpty() && asText.all { it.isDigit() }) {
        val bi = BigInteger(asText)
        return UUID(bi.shiftRight(64).toLong(), bi.toLong())
    }

    if (kidBytes.size < 16) {
        kidBytes += ByteArray(16 - kidBytes.size)
    }

    return kidBytes.toByteString(0, 16).uuidFromByteString()
}

/** Convert a Base64-encoded KID [String] to a [UUID]. */
fun String.kidToUuid(): UUID = Base64.decode(this).toByteString().kidToUuid()

/** Escape the five XML predefined entities so interpolated text cannot break the document. */
fun escapeXml(value: String): String = buildString(value.length) {
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

/** True when [needle] occurs anywhere in this array. */
fun ByteArray.containsSubarray(needle: ByteArray): Boolean {
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

/** Reverse of [escapeXml] for the five predefined entities and numeric character references. */
fun unescapeXml(value: String): String {
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
