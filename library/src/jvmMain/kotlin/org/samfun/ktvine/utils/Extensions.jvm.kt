package org.samfun.ktvine.utils

import okio.ByteString
import okio.ByteString.Companion.decodeHex
import java.nio.charset.StandardCharsets
import java.util.UUID

actual fun String.encodeToUtf16LE(): ByteArray {
    return this.toByteArray(StandardCharsets.UTF_16LE)
}

actual fun ByteArray.decodeToStringUtf16LE(): String {
    return String(this, StandardCharsets.UTF_16LE)
}

actual fun ByteString.uuidFromHexByteString(): UUID =
    this.string(StandardCharsets.UTF_8).decodeHex().uuidFromByteString()

actual fun ByteArray.toUTF8(): String {
    return this.toString(StandardCharsets.UTF_8)
}