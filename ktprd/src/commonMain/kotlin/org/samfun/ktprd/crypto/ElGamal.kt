package org.samfun.ktprd.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import org.samfun.ktvine.crypto.randomBytes
import org.samfun.ktvine.utils.ValueException

/**
 * EC-ElGamal over P-256, the key exchange PlayReady uses in both directions.
 *
 * The client encrypts its session point to the license server's WMRM key when building a
 * challenge, and the server encrypts the content-key material to the device's encryption key in
 * the XMR license it returns.
 */
internal object ElGamal {

    /** Two points, four coordinates, 32 bytes each. */
    const val CIPHERTEXT_SIZE: Int = P256.FIELD_SIZE * 4

    /**
     * Encrypt [message] to [publicPoint], returning `P1.x‖P1.y‖P2.x‖P2.y`.
     *
     * The ephemeral scalar is drawn fresh for every call; reusing one across two messages under
     * the same public key would reveal their difference.
     */
    fun encrypt(message: EcPoint, publicPoint: EcPoint): ByteArray {
        val ephemeral = randomScalar()
        val p1 = P256.scalarMultiply(ephemeral, P256.G)
        val p2 = P256.add(message, P256.scalarMultiply(ephemeral, publicPoint))
        return p1.encode() + p2.encode()
    }

    /**
     * Recover the message point from a [CIPHERTEXT_SIZE]-byte pair and return its X coordinate.
     *
     * Only X is returned because that is all PlayReady puts key material in; the Y coordinate
     * carries nothing the caller needs.
     */
    fun decrypt(ciphertext: ByteArray, privateScalar: BigInteger): ByteArray {
        if (ciphertext.size != CIPHERTEXT_SIZE) {
            throw ValueException("An ElGamal ciphertext is ${ciphertext.size} bytes, expected $CIPHERTEXT_SIZE")
        }
        val half = CIPHERTEXT_SIZE / 2
        val p1 = P256.decodePoint(ciphertext.copyOfRange(0, half))
        val p2 = P256.decodePoint(ciphertext.copyOfRange(half, CIPHERTEXT_SIZE))

        val shared = P256.scalarMultiply(privateScalar, p1)
        val message = P256.subtract(p2, shared)
        if (message.isInfinity) throw ValueException("ElGamal decryption produced the point at infinity")
        return P256.toFixed32(message.x)
    }

    /** A uniform scalar in `[1, n)`, by rejection so no modulo bias is introduced. */
    fun randomScalar(): BigInteger {
        while (true) {
            val candidate = P256.fromBytes(randomBytes(P256.FIELD_SIZE))
            if (candidate.signum() > 0 && candidate < P256.N) return candidate
        }
    }
}
