@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd.core

import org.samfun.ktprd.crypto.aesEcbEncrypt
import org.samfun.ktprd.crypto.sha1
import org.samfun.ktprd.utils.InvalidChecksumException
import org.samfun.ktprd.utils.InvalidWrmHeaderException
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.core.SignedKeyId
import org.samfun.ktvine.crypto.constantTimeEquals
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.toLittleEndianByteArray
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * A `WRMHEADER` ready to be turned into a license challenge.
 *
 * This wraps ktvine's [PlayreadyHeader] parse with the two things only a CDM needs: the protocol
 * version to declare, and the ability to check a decrypted content key against the header's
 * advertised checksum.
 *
 * [xml] is the document verbatim. A challenge embeds it inside signed bytes, so re-serializing it
 * — even into equivalent XML — would change what the signature covers.
 */
public class WrmHeader private constructor(
    public val xml: String,
    public val header: PlayreadyHeader,
) {
    public val version: String get() = header.version

    public val keyIds: List<SignedKeyId> get() = header.signedKeyIds

    /**
     * The `<Version>` a challenge for this header must declare.
     *
     * A server reads it to decide which protocol features the client is claiming; sending the
     * wrong one against a 4.3.0.0 header gets the request rejected outright.
     */
    public val protocolVersion: Int
        get() = when (version) {
            "4.3.0.0" -> 5
            "4.2.0.0" -> 4
            else -> 1
        }

    override fun toString(): String = "WrmHeader(version=$version, keyIds=${keyIds.map { it.value }})"

    /**
     * Check a decrypted content key against the checksum the header advertises for [kid].
     *
     * This is what confirms the key the license handed back is the key this content was encrypted
     * with; a mismatch means the right key id came back with the wrong key.
     *
     * @throws InvalidChecksumException if the header names no such key id, carries no checksum for
     *   it, or declares an algorithm with no defined checksum
     */
    public suspend fun verifyChecksum(kid: Uuid, contentKey: ByteArray): Boolean {
        val signed = keyIds.firstOrNull { it.value == kid }
            ?: throw InvalidChecksumException("This header declares no key id $kid")
        val checksum = signed.checksum
            ?: throw InvalidChecksumException("This header declares no checksum for key id $kid")

        val computed = when (signed.algId) {
            "AESCTR" -> aesEcbEncrypt(contentKey, kid.toLittleEndianByteArray()).copyOf(AESCTR_CHECKSUM_SIZE)
            "COCKTAIL" -> cocktailChecksum(contentKey)
            else -> throw InvalidChecksumException(
                "Key id $kid declares algorithm ${signed.algId}, which has no defined checksum",
            )
        }

        return constantTimeEquals(computed, checksum)
    }

    /** Five rounds of SHA-1 over the content key, right-padded to 21 bytes. */
    private suspend fun cocktailChecksum(contentKey: ByteArray): ByteArray {
        var buffer = contentKey.copyOf(COCKTAIL_BUFFER_SIZE)
        repeat(COCKTAIL_ROUNDS) { buffer = sha1(buffer) }
        return buffer.copyOf(COCKTAIL_CHECKSUM_SIZE)
    }

    public companion object {
        private const val AESCTR_CHECKSUM_SIZE = 8
        private const val COCKTAIL_BUFFER_SIZE = 21
        private const val COCKTAIL_CHECKSUM_SIZE = 7
        private const val COCKTAIL_ROUNDS = 5

        /**
         * Parse a `WRMHEADER` document.
         *
         * @throws InvalidWrmHeaderException if it is not a supported header
         */
        public fun parse(xml: String): WrmHeader {
            val header = try {
                PlayreadyHeader.parse(xml)
            } catch (e: ValueException) {
                throw InvalidWrmHeaderException("Not a usable WRMHEADER: ${e.message}")
            }
            return WrmHeader(xml, header)
        }

        /**
         * Every header carried by a PlayReady PSSH box, PlayReady Object, or bare `WRMHEADER`.
         *
         * @throws InvalidWrmHeaderException if the box carries no PlayReady header
         */
        public fun from(pssh: PSSH): List<WrmHeader> {
            val documents = try {
                pssh.wrmHeaders()
            } catch (e: ValueException) {
                throw InvalidWrmHeaderException("This PSSH carries no PlayReady header: ${e.message}")
            }
            return documents.map { parse(it) }
        }

        /** The single header in [pssh], or the first when it carries several. */
        public fun from(base64Pssh: String): WrmHeader = if (base64Pssh.trimStart().startsWith("<WRMHEADER")) {
            parse(base64Pssh)
        } else {
            from(PSSH(base64Pssh)).first()
        }
    }
}
