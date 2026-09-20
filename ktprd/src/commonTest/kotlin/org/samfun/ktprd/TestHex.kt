package org.samfun.ktprd

/** Decode a lowercase or uppercase hex string; the inverse of ktvine's `toHexString`. */
internal fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "A hex string must have an even length, got $length" }
    return ByteArray(length / 2) { i ->
        ((digit(this[i * 2]) shl 4) or digit(this[i * 2 + 1])).toByte()
    }
}

private fun digit(c: Char): Int = when (c) {
    in '0'..'9' -> c - '0'
    in 'a'..'f' -> c - 'a' + 10
    in 'A'..'F' -> c - 'A' + 10
    else -> throw IllegalArgumentException("Not a hex digit: $c")
}
