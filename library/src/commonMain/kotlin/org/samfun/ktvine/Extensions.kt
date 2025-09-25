package org.samfun.ktvine

import okio.Buffer
import okio.ByteString
import okio.ByteString.Companion.decodeHex
import org.mp4parser.tools.UUIDConverter
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

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

fun ByteArray.toLittleInt(): Int = ByteBuffer.wrap(this).order(ByteOrder.LITTLE_ENDIAN).int

fun ByteArray.toBuffer(): Buffer = Buffer().write(this)
