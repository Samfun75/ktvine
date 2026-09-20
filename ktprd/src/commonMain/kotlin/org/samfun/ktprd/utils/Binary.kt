package org.samfun.ktprd.utils

/**
 * A bounds-checked cursor over a byte array.
 *
 * PlayReady's structures are length-prefixed and self-describing, so a truncated or hostile blob
 * would otherwise read past its own end; every accessor here reports [position] in the failure so
 * a bad offset is traceable.
 */
internal class ByteReader(
    private val source: ByteArray,
    private val start: Int = 0,
    private val end: Int = source.size,
) {
    var position: Int = start
        private set

    val remaining: Int get() = end - position

    fun require(count: Int, what: String) {
        if (count < 0 || count > remaining) {
            throw org.samfun.ktvine.utils.ValueException(
                "Truncated $what: need $count bytes at offset $position, $remaining remain",
            )
        }
    }

    fun u8(what: String): Int {
        require(1, what)
        return source[position++].toInt() and 0xFF
    }

    fun u16(what: String): Int {
        require(2, what)
        return (u8(what) shl 8) or u8(what)
    }

    fun u16Le(what: String): Int {
        require(2, what)
        val low = u8(what)
        return low or (u8(what) shl 8)
    }

    /** Reads a `u32` into a [Long] so lengths near `0xFFFFFFFF` stay positive. */
    fun u32(what: String): Long {
        require(4, what)
        var value = 0L
        repeat(4) { value = (value shl 8) or u8(what).toLong() }
        return value
    }

    fun u32Le(what: String): Long {
        require(4, what)
        var value = 0L
        repeat(4) { value = value or (u8(what).toLong() shl (8 * it)) }
        return value
    }

    fun u64(what: String): Long {
        require(8, what)
        var value = 0L
        repeat(8) { value = (value shl 8) or u8(what).toLong() }
        return value
    }

    fun u64Le(what: String): Long {
        require(8, what)
        var value = 0L
        repeat(8) { value = value or (u8(what).toLong() shl (8 * it)) }
        return value
    }

    fun bytes(count: Int, what: String): ByteArray {
        require(count, what)
        val out = source.copyOfRange(position, position + count)
        position += count
        return out
    }

    /** A length that must fit an [Int] to be usable as an array size. */
    fun countOf(value: Long, what: String): Int {
        if (value < 0 || value > remaining) {
            throw org.samfun.ktvine.utils.ValueException(
                "Implausible $what length $value at offset $position, $remaining bytes remain",
            )
        }
        return value.toInt()
    }

    fun skip(count: Int, what: String) {
        require(count, what)
        position += count
    }

    /** The bytes between [from] and the current position, for structures that sign their own encoding. */
    fun sliceSince(from: Int): ByteArray = source.copyOfRange(from, position)

    /** A reader over the next [count] bytes; this reader advances past them. */
    fun slice(count: Int, what: String): ByteReader {
        require(count, what)
        val child = ByteReader(source, position, position + count)
        position += count
        return child
    }
}

/** Accumulates big-endian fields; PlayReady structures are big-endian apart from the PlayReady Object. */
internal class ByteWriter {
    private var buffer = ByteArray(64)
    private var length = 0

    val size: Int get() = length

    private fun ensure(extra: Int) {
        if (length + extra <= buffer.size) return
        var capacity = buffer.size
        while (capacity < length + extra) capacity *= 2
        buffer = buffer.copyOf(capacity)
    }

    fun u8(value: Int): ByteWriter {
        ensure(1)
        buffer[length++] = value.toByte()
        return this
    }

    fun u16(value: Int): ByteWriter = u8(value ushr 8).u8(value)

    fun u16Le(value: Int): ByteWriter = u8(value).u8(value ushr 8)

    fun u32(value: Long): ByteWriter = u8((value ushr 24).toInt()).u8((value ushr 16).toInt())
        .u8((value ushr 8).toInt()).u8(value.toInt())

    fun u32(value: Int): ByteWriter = u32(value.toLong() and 0xFFFFFFFFL)

    fun u32Le(value: Int): ByteWriter {
        val v = value.toLong() and 0xFFFFFFFFL
        return u8(v.toInt()).u8((v ushr 8).toInt()).u8((v ushr 16).toInt()).u8((v ushr 24).toInt())
    }

    fun bytes(value: ByteArray): ByteWriter {
        ensure(value.size)
        value.copyInto(buffer, length)
        length += value.size
        return this
    }

    /** Zero-fills to the next 4-byte boundary, the padding every `bcert` string field carries. */
    fun padTo4(): ByteWriter {
        while (length % 4 != 0) u8(0)
        return this
    }

    fun toByteArray(): ByteArray = buffer.copyOf(length)
}

/** Round up to the next multiple of four, the alignment `bcert` string fields are stored at. */
internal fun align4(value: Int): Int = (value + 3) / 4 * 4

/** Decode a UTF-8 field that was zero-padded out to its alignment. */
internal fun ByteArray.decodeNulPadded(): String {
    var end = size
    while (end > 0 && this[end - 1] == 0.toByte()) end--
    return copyOf(end).decodeToString()
}
