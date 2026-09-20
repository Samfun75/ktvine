package org.samfun.ktprd

import com.ionspin.kotlin.bignum.integer.BigInteger
import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.crypto.P256
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * RFC 6979 appendix A.2.5 — the published P-256 / SHA-256 deterministic-ECDSA vectors.
 *
 * Deterministic nonces are what make these assertable at all: with a random k there would be
 * nothing to compare against but a round trip through our own verifier.
 */
class EcdsaTest {

    private val privateScalar =
        BigInteger.parseString("c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721", 16)

    private val publicPoint = P256.decodePoint(
        (
            "60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
                "7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299"
            ).hexToBytes(),
    )

    @Test
    fun `test the public point is the one RFC 6979 derives from the private key`() {
        assertEquals(publicPoint, P256.publicPoint(privateScalar))
    }

    @Test
    fun `test signing sample matches the RFC 6979 vector`() = runTest {
        val signature = Ecdsa.sign(privateScalar, "sample".encodeToByteArray())
        assertEquals(
            "efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716" +
                "f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
            signature.toHexString(),
        )
    }

    @Test
    fun `test signing test matches the RFC 6979 vector`() = runTest {
        val signature = Ecdsa.sign(privateScalar, "test".encodeToByteArray())
        assertEquals(
            "f1abb023518351cd71d881567b1ea663ed3efcf6c5132b354f28d3b0b7d38367" +
                "019f4113742a2b14bd25926b49c649155f267e60d3814b4c0cc84250e46f0083",
            signature.toHexString(),
        )
    }

    @Test
    fun `test a signature verifies against the raw public key bytes`() = runTest {
        val message = "sample".encodeToByteArray()
        val signature = Ecdsa.sign(privateScalar, message)
        assertTrue(Ecdsa.verify(publicPoint.encode(), message, signature))
    }

    @Test
    fun `test verification rejects a tampered message`() = runTest {
        val signature = Ecdsa.sign(privateScalar, "sample".encodeToByteArray())
        assertFalse(Ecdsa.verify(publicPoint, "samplf".encodeToByteArray(), signature))
    }

    @Test
    fun `test verification rejects a tampered signature`() = runTest {
        val message = "sample".encodeToByteArray()
        val signature = Ecdsa.sign(privateScalar, message)
        signature[0] = (signature[0].toInt() xor 1).toByte()
        assertFalse(Ecdsa.verify(publicPoint, message, signature))
    }

    @Test
    fun `test verification rejects a signature of the wrong length`() = runTest {
        assertFalse(Ecdsa.verify(publicPoint, "sample".encodeToByteArray(), ByteArray(63)))
    }

    @Test
    fun `test verification rejects a public key that is not on the curve`() = runTest {
        val message = "sample".encodeToByteArray()
        val signature = Ecdsa.sign(privateScalar, message)
        assertFalse(Ecdsa.verify(ByteArray(64), message, signature))
    }
}
