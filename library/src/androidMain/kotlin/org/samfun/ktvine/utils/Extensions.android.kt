package org.samfun.ktvine.utils

import okio.ByteString
import okio.ByteString.Companion.decodeHex
import java.util.UUID

actual fun String.encodeToUtf16LE(): ByteArray {
    return this.toByteArray(Charsets.UTF_16LE)
}

actual fun ByteArray.decodeToStringUtf16LE(): String {
    return String(this, Charsets.UTF_16LE)
}

actual fun ByteString.uuidFromHexByteString(): UUID =
    this.string(Charsets.UTF_8).decodeHex().uuidFromByteString()

actual fun ByteArray.toUTF8(): String {
    return this.toString(Charsets.UTF_8)
}