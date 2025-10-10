package org.samfun.ktvine.utils

import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import okio.ByteString.Companion.toByteString
import org.mp4parser.tools.UUIDConverter
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID
import kotlin.collections.plus
import kotlin.io.encoding.Base64

fun UUID.toByteArray(): ByteArray = UUIDConverter.convert(this)

fun ByteString.uuidFromByteString(): UUID = UUIDConverter.convert(this.toByteArray())

fun ByteString.uuidFromHexByteString(): UUID =
    this.string(Charsets.UTF_8).decodeHex().uuidFromByteString()

fun ByteString.uuidFromByteArray(): UUID {
    val bigInt = BigInteger(1, this.toByteArray())
    val (mostSigBits, leastSigBits) = with(bigInt) {
        val most = shiftRight(64).toLong()
        val least = and(BigInteger("FFFFFFFFFFFFFFFF", 16)).toLong()
        most to least
    }
    return UUID(mostSigBits, leastSigBits)
}

fun Int.toLEU16(): ByteArray = byteArrayOf(
    (this and 0xFF).toByte(),
    ((this ushr 8) and 0xFF).toByte(),
)

fun Int.toLEU32(): ByteArray = byteArrayOf(
    (this and 0xFF).toByte(),
    ((this ushr 8) and 0xFF).toByte(),
    ((this ushr 16) and 0xFF).toByte(),
    ((this ushr 24) and 0xFF).toByte()
)

fun ByteArray.toHexString(): String = joinToString("") { (it.toInt() and 0xFF).toString(16).padStart(2, '0') }

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

    if (kidBytes.toString(Charsets.UTF_8).all { it.isDigit() }) {
        val bi = BigInteger(kidBytes.toString(Charsets.UTF_8))
        return UUID(bi.shiftRight(64).toLong(), bi.toLong())
    }

    if (kidBytes.size < 16) {
        kidBytes += ByteArray(16 - kidBytes.size)
    }

    return kidBytes.toByteString(0, 16).uuidFromByteString()
}