package org.samfun.ktvine.utils

import com.squareup.wire.Message

/**
 * Decode a protobuf message and reject a partial parse.
 *
 * Protobuf decoders happily accept a prefix of a malformed blob, and several Widevine
 * messages are mutually parseable — a bare `SignedDrmCertificate` also decodes as a
 * `SignedMessage`. Comparing the re-encoding against the input is how pywidevine tells
 * them apart (devine-dl/pywidevine#41).
 *
 * @throws DecodeException if decoding fails or the re-encoding differs from [bytes]
 */
internal inline fun <T : Message<*, *>> decodeExact(bytes: ByteArray, what: String, decode: (ByteArray) -> T): T {
    val message = try {
        decode(bytes)
    } catch (e: Throwable) {
        throw DecodeException("Failed to parse $what, $e")
    }
    if (!message.encode().contentEquals(bytes)) {
        throw DecodeException("Failed to parse $what, partial parse")
    }
    return message
}

/** [decodeExact], returning `null` instead of throwing. */
internal inline fun <T : Message<*, *>> decodeExactOrNull(bytes: ByteArray, decode: (ByteArray) -> T): T? = try {
    decodeExact(bytes, "message", decode)
} catch (_: DecodeException) {
    null
}
