package org.samfun.ktprd.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import org.samfun.ktvine.crypto.hmacSha256
import org.samfun.ktvine.utils.ValueException

/**
 * ECDSA over P-256 with SHA-256, producing PlayReady's raw `r‖s` signatures.
 *
 * PlayReady carries signatures as 64 raw bytes, never DER, both in `bcert` objects and in the
 * `SignatureValue` of a license challenge.
 *
 * The nonce is derived deterministically per RFC 6979 rather than drawn from the RNG. That makes
 * signing reproducible — the same key and message always yield the same signature — so the
 * challenge builder can be pinned by a fixture instead of only by a round trip, and a repeated
 * nonce cannot leak the private key.
 */
internal object Ecdsa {

    const val SIGNATURE_SIZE: Int = P256.FIELD_SIZE * 2

    suspend fun sign(privateScalar: BigInteger, message: ByteArray): ByteArray {
        val digest = sha256(message)
        val e = truncate(digest)

        var attempt = ByteArray(0)
        while (true) {
            val k = deterministicNonce(privateScalar, digest, attempt)
            val point = P256.scalarMultiply(k, P256.G)
            val r = point.x.mod(P256.N)
            if (r.isZero()) {
                attempt += 0
                continue
            }
            val s = (k.modInverse(P256.N) * (e + privateScalar * r)).mod(P256.N)
            if (s.isZero()) {
                attempt += 0
                continue
            }
            return P256.toFixed32(r) + P256.toFixed32(s)
        }
    }

    suspend fun verify(publicPoint: EcPoint, message: ByteArray, signature: ByteArray): Boolean {
        if (signature.size != SIGNATURE_SIZE) return false

        val r = P256.fromBytes(signature.copyOfRange(0, P256.FIELD_SIZE))
        val s = P256.fromBytes(signature.copyOfRange(P256.FIELD_SIZE, SIGNATURE_SIZE))
        if (r.signum() <= 0 || r >= P256.N) return false
        if (s.signum() <= 0 || s >= P256.N) return false
        if (publicPoint.isInfinity || !P256.isOnCurve(publicPoint)) return false

        val e = truncate(sha256(message))
        val sInv = s.modInverse(P256.N)
        val u1 = (e * sInv).mod(P256.N)
        val u2 = (r * sInv).mod(P256.N)

        // Either scalar can legitimately be zero, and scalarMultiply rejects that.
        val p1 = if (u1.isZero()) EcPoint.INFINITY else P256.scalarMultiply(u1, P256.G)
        val p2 = if (u2.isZero()) EcPoint.INFINITY else P256.scalarMultiply(u2, publicPoint)
        val sum = P256.add(p1, p2)
        if (sum.isInfinity) return false

        return sum.x.mod(P256.N) == r
    }

    /** Verify against a raw 64-byte `X‖Y` public key, the form every PlayReady structure stores. */
    suspend fun verify(publicKeyBytes: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val point = try {
            P256.decodePoint(publicKeyBytes)
        } catch (e: ValueException) {
            return false
        }
        return verify(point, message, signature)
    }

    /** FIPS 186-4 bit truncation; P-256's order is 256 bits, so the digest is used whole. */
    private fun truncate(digest: ByteArray): BigInteger {
        val value = P256.fromBytes(digest)
        val excess = digest.size * 8 - P256.N.bitLength()
        return if (excess > 0) value.shr(excess) else value
    }

    /**
     * RFC 6979 §3.2 with HMAC-SHA256.
     *
     * [extraEntropy] lets [sign] ask for a different nonce in the (vanishingly unlikely) case
     * that r or s comes out zero, which is where RFC 6979 §3.2 step h would loop.
     */
    private suspend fun deterministicNonce(
        privateScalar: BigInteger,
        digest: ByteArray,
        extraEntropy: ByteArray,
    ): BigInteger {
        val holen = 32
        var v = ByteArray(holen) { 0x01 }
        var k = ByteArray(holen)

        // RFC 6979 bits2octets: the truncated digest is reduced mod n before it is encoded.
        val seed = P256.toFixed32(privateScalar) + P256.toFixed32(truncate(digest).mod(P256.N)) + extraEntropy

        k = hmacSha256(k, v + byteArrayOf(0x00) + seed)
        v = hmacSha256(k, v)
        k = hmacSha256(k, v + byteArrayOf(0x01) + seed)
        v = hmacSha256(k, v)

        while (true) {
            v = hmacSha256(k, v)
            val candidate = P256.fromBytes(v)
            if (candidate.signum() > 0 && candidate < P256.N) return candidate
            k = hmacSha256(k, v + byteArrayOf(0x00))
            v = hmacSha256(k, v)
        }
    }
}
