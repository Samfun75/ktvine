package org.samfun.ktvine.utils

import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.mp4parser.tools.UUIDConverter
import java.math.BigInteger
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
fun UUID.toByteArray(): ByteArray = UUIDConverter.convert(this)

/** Interpret this [ByteString] as a 16-byte [UUID]. */
fun ByteString.uuidFromByteString(): UUID = UUIDConverter.convert(this.toByteArray())

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
 * Convert a KID stored in a variety of formats (base64/number/bytes) to a [UUID].
 * Accepts nullable input and returns UUID(0,0) for missing KIDs.
 */
fun ByteString?.kidToUuid(): UUID {
    var kidBytes = this?.toByteArray()
    if (kidBytes == null || kidBytes.isEmpty()) {
        return UUID(0, 0)
    }

    try {
        kidBytes = Base64.decode(kidBytes)
    } catch (_: IllegalArgumentException) {
        // not base64
    }

    if (kidBytes.toUTF8().all { it.isDigit() }) {
        val bi = BigInteger(kidBytes.toUTF8())
        return UUID(bi.shiftRight(64).toLong(), bi.toLong())
    }

    if (kidBytes.size < 16) {
        kidBytes += ByteArray(16 - kidBytes.size)
    }

    return kidBytes.toByteString(0, 16).uuidFromByteString()
}