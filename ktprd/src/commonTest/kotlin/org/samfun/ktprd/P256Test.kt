package org.samfun.ktprd

import com.ionspin.kotlin.bignum.integer.BigInteger
import org.samfun.ktprd.crypto.EcPoint
import org.samfun.ktprd.crypto.P256
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * NIST P-256 vectors, from NIST's routines for the prime curves.
 *
 * These run on every target, which is the point: the curve is hand-written common code and a
 * wrong bit in it means every content key comes out wrong rather than failing loudly.
 */
class P256Test {

    private fun scalar(decimal: String) = BigInteger.parseString(decimal, 10)

    private fun assertPoint(expectedX: String, expectedY: String, actual: EcPoint) {
        assertEquals(expectedX, P256.toFixed32(actual.x).toHexString())
        assertEquals(expectedY, P256.toFixed32(actual.y).toHexString())
    }

    @Test
    fun `test the base point is on the curve`() {
        assertTrue(P256.isOnCurve(P256.G))
    }

    @Test
    fun `test scalar multiplication of the base point matches the NIST vectors`() {
        assertPoint(
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            P256.scalarMultiply(scalar("1"), P256.G),
        )
        assertPoint(
            "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978",
            "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1",
            P256.scalarMultiply(scalar("2"), P256.G),
        )
        assertPoint(
            "5ecbe4d1a6330a44c8f7ef951d4bf165e6c6b721efada985fb41661bc6e7fd6c",
            "8734640c4998ff7e374b06ce1a64a2ecd82ab036384fb83d9a79b127a27d5032",
            P256.scalarMultiply(scalar("3"), P256.G),
        )
        assertPoint(
            "e2534a3532d08fbba02dde659ee62bd0031fe2db785596ef509302446b030852",
            "e0f1575a4c633cc719dfee5fda862d764efc96c3f30ee0055c42c23f184ed8c6",
            P256.scalarMultiply(scalar("4"), P256.G),
        )
        assertPoint(
            "f0454dc6971abae7adfb378999888265ae03af92de3a0ef163668c63e59b9d5f",
            "b5b93ee3592e2d1f4e6594e51f9643e62a3b21ce75b5fa3f47e59cde0d034f36",
            P256.scalarMultiply(scalar("15"), P256.G),
        )
        assertPoint(
            "339150844ec15234807fe862a86be77977dbfb3ae3d96f4c22795513aeaab82f",
            "b1c14ddfdc8ec1b2583f51e85a5eb3a155840f2034730e9b5ada38b674336a21",
            P256.scalarMultiply(scalar("112233445566778899"), P256.G),
        )
    }

    @Test
    fun `test point addition agrees with repeated doubling`() {
        val two = P256.scalarMultiply(scalar("2"), P256.G)
        val three = P256.scalarMultiply(scalar("3"), P256.G)
        val five = P256.scalarMultiply(scalar("5"), P256.G)

        assertEquals(five, P256.add(two, three))
        assertEquals(three, P256.subtract(five, two))
        assertEquals(P256.G, P256.subtract(three, two))
    }

    @Test
    fun `test adding a point to its negation gives infinity`() {
        val p = P256.scalarMultiply(scalar("7"), P256.G)
        assertTrue(P256.add(p, P256.negate(p)).isInfinity)
        assertTrue(P256.subtract(p, p).isInfinity)
    }

    @Test
    fun `test infinity is the additive identity`() {
        val p = P256.scalarMultiply(scalar("9"), P256.G)
        assertEquals(p, P256.add(p, EcPoint.INFINITY))
        assertEquals(p, P256.add(EcPoint.INFINITY, p))
    }

    @Test
    fun `test a point round trips through its 64 byte encoding`() {
        val p = P256.scalarMultiply(scalar("112233445566778899"), P256.G)
        val encoded = p.encode()
        assertEquals(64, encoded.size)
        assertEquals(p, P256.decodePoint(encoded))
    }

    @Test
    fun `test a coordinate always encodes to 32 bytes`() {
        // A small value must still left-pad rather than shrink, which is where pyplayready's
        // even-byte-length encoder emits 30 bytes and silently changes the wire format.
        assertEquals(
            "0000000000000000000000000000000000000000000000000000000000000001",
            P256.toFixed32(BigInteger.ONE).toHexString(),
        )
    }

    @Test
    fun `test a point off the curve is rejected`() {
        val bogus = P256.toFixed32(BigInteger.ONE) + P256.toFixed32(BigInteger.fromInt(2))
        assertFailsWith<org.samfun.ktvine.utils.ValueException> { P256.decodePoint(bogus) }
        assertFalse(P256.isOnCurve(EcPoint.of(BigInteger.ONE, BigInteger.fromInt(2))))
    }

    @Test
    fun `test a scalar outside the group order is rejected`() {
        assertFailsWith<org.samfun.ktvine.utils.ValueException> { P256.scalarMultiply(BigInteger.ZERO, P256.G) }
        assertFailsWith<org.samfun.ktvine.utils.ValueException> { P256.scalarMultiply(P256.N, P256.G) }
    }
}
