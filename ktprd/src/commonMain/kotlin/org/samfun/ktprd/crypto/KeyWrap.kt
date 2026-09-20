package org.samfun.ktprd.crypto

import org.samfun.ktvine.crypto.aesCmac
import org.samfun.ktvine.utils.ValueException

/**
 * Unwrapping for a protected device group key (`zgpriv_protected.dat`).
 *
 * The wrapping key is not stored anywhere: it is derived from two fixed constants through the
 * NIST SP 800-108r1 counter-mode KDF, with AES-CMAC as the PRF. The wrapped blob is then an
 * ordinary RFC 3394 AES key wrap.
 */
internal object KeyWrap {

    /** SP 800-108 label, the "certificate private keys wrap" derivation. */
    private val LABEL = byteArrayOf(
        0x9c.toByte(), 0xe9.toByte(), 0x34, 0x32, 0xc7.toByte(), 0xd7.toByte(), 0x40, 0x16,
        0xba.toByte(), 0x68, 0x47, 0x63, 0xf8.toByte(), 0x01, 0xe1.toByte(), 0x36,
    )

    /** SP 800-108 key-derivation key. */
    private val DERIVATION_KEY = byteArrayOf(
        0x8B.toByte(), 0x22, 0x2F, 0xFD.toByte(), 0x1E, 0x76, 0x19, 0x56,
        0x59, 0xCF.toByte(), 0x27, 0x03, 0x89.toByte(), 0x8C.toByte(), 0x42, 0x7F,
    )

    /** RFC 3394 default initial value. */
    private val RFC3394_IV = ByteArray(8) { 0xA6.toByte() }

    private const val PRIVATE_KEY_SIZE = 32

    /**
     * Unwrap a protected group key, returning the 32-byte private scalar.
     *
     * The unwrapped blob is 48 bytes; the trailing 16 are random padding and are discarded.
     */
    suspend fun unwrapGroupKey(wrapped: ByteArray): ByteArray {
        val unwrapped = aesKeyUnwrap(deriveWrappingKey(), wrapped)
        if (unwrapped.size < PRIVATE_KEY_SIZE) {
            throw ValueException("Unwrapped group key is ${unwrapped.size} bytes, expected at least $PRIVATE_KEY_SIZE")
        }
        return unwrapped.copyOf(PRIVATE_KEY_SIZE)
    }

    /** SP 800-108r1 counter mode, one iteration, 128 bits of output. */
    suspend fun deriveWrappingKey(): ByteArray {
        val input = byteArrayOf(1) + LABEL + byteArrayOf(0) + ByteArray(16) + byteArrayOf(0, 128.toByte())
        return aesCmac(DERIVATION_KEY, input)
    }

    /**
     * RFC 3394 AES key unwrap.
     *
     * @throws ValueException if the integrity check fails, which means the wrong wrapping key or a
     *   corrupt blob — never return the plaintext anyway, as that hands back garbage as a key.
     */
    suspend fun aesKeyUnwrap(wrappingKey: ByteArray, wrapped: ByteArray): ByteArray {
        if (wrapped.size < 24 || wrapped.size % 8 != 0) {
            throw ValueException("A wrapped key is ${wrapped.size} bytes; expected a multiple of 8, at least 24")
        }

        val n = wrapped.size / 8 - 1
        var a = wrapped.copyOf(8)
        val r = Array(n) { wrapped.copyOfRange((it + 1) * 8, (it + 2) * 8) }

        for (j in 5 downTo 0) {
            for (i in n downTo 1) {
                val t = (n * j + i).toLong()
                val block = a.xorCounter(t) + r[i - 1]
                val decrypted = aesEcbDecrypt(wrappingKey, block)
                a = decrypted.copyOf(8)
                r[i - 1] = decrypted.copyOfRange(8, 16)
            }
        }

        if (!a.contentEquals(RFC3394_IV)) throw ValueException("Key unwrap integrity check failed")

        val out = ByteArray(n * 8)
        for (i in 0 until n) r[i].copyInto(out, i * 8)
        return out
    }

    /** XOR a 64-bit big-endian counter into the trailing bytes of an 8-byte block. */
    private fun ByteArray.xorCounter(counter: Long): ByteArray {
        val out = copyOf()
        for (i in 0 until 8) {
            out[7 - i] = (out[7 - i].toInt() xor ((counter ushr (8 * i)) and 0xFF).toInt()).toByte()
        }
        return out
    }
}
