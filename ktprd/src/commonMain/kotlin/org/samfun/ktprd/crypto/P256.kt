package org.samfun.ktprd.crypto

import com.ionspin.kotlin.bignum.integer.BigInteger
import com.ionspin.kotlin.bignum.integer.Sign
import org.samfun.ktvine.utils.ValueException

/**
 * A point on NIST P-256, in affine coordinates.
 *
 * [x] and [y] are meaningless when [isInfinity] is true.
 */
internal class EcPoint private constructor(val x: BigInteger, val y: BigInteger, val isInfinity: Boolean) {
    fun encode(): ByteArray {
        if (isInfinity) throw ValueException("Cannot encode the point at infinity")
        return P256.toFixed32(x) + P256.toFixed32(y)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is EcPoint) return false
        if (isInfinity || other.isInfinity) return isInfinity == other.isInfinity
        return x == other.x && y == other.y
    }

    override fun hashCode(): Int = if (isInfinity) 0 else 31 * x.hashCode() + y.hashCode()

    override fun toString(): String = if (isInfinity) "EcPoint(infinity)" else "EcPoint(x=$x, y=$y)"

    companion object {
        val INFINITY: EcPoint = EcPoint(BigInteger.ZERO, BigInteger.ZERO, true)

        fun of(x: BigInteger, y: BigInteger): EcPoint = EcPoint(x, y, false)
    }
}

/**
 * NIST P-256 (secp256r1) field and group arithmetic.
 *
 * Written here because cryptography-kotlin exposed no point arithmetic as of 0.5.0 — only
 * ECDSA and ECDH, and ECDH yields just the shared secret's X coordinate. PlayReady's ElGamal key
 * exchange needs whole points, so the curve is implemented in common code and pinned by NIST
 * vectors, the same call the in-tree AES-CMAC made for the same reason.
 *
 * **This is not constant-time.** The scalar ladder branches on key bits and the underlying
 * BigInteger is not hardened. That matches the threat model of a client-side CDM holding its own
 * device keys locally; do not reuse it where an attacker can measure the machine doing the work.
 */
internal object P256 {

    /** Field prime. */
    val P: BigInteger = hex("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff")

    /** Curve coefficient b. The coefficient a is fixed at p - 3 and is folded into the formulas. */
    val B: BigInteger = hex("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b")

    /** Order of the base point. */
    val N: BigInteger = hex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")

    /** Base point. */
    val G: EcPoint = EcPoint.of(
        hex("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"),
        hex("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"),
    )

    /** Bytes per coordinate and per scalar. */
    const val FIELD_SIZE: Int = 32

    private val TWO = BigInteger.fromInt(2)
    private val THREE = BigInteger.fromInt(3)
    private val FOUR = BigInteger.fromInt(4)
    private val EIGHT = BigInteger.fromInt(8)

    private fun hex(value: String): BigInteger = BigInteger.parseString(value, 16)

    /** Big-endian, always exactly [FIELD_SIZE] bytes — never the reference's variable-width form. */
    fun toFixed32(value: BigInteger): ByteArray {
        if (value.signum() < 0) throw ValueException("Cannot encode a negative field element")
        val digits = value.toString(16)
        if (digits.length > FIELD_SIZE * 2) throw ValueException("Field element does not fit in $FIELD_SIZE bytes")
        val padded = digits.padStart(FIELD_SIZE * 2, '0')
        return ByteArray(FIELD_SIZE) { i ->
            ((hexDigit(padded[i * 2]) shl 4) or hexDigit(padded[i * 2 + 1])).toByte()
        }
    }

    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw ValueException("Not a hex digit: $c")
    }

    fun fromBytes(bytes: ByteArray): BigInteger = BigInteger.fromByteArray(bytes, Sign.POSITIVE)

    /** Decode a 64-byte uncompressed X-then-Y point, rejecting anything not on the curve. */
    fun decodePoint(bytes: ByteArray): EcPoint {
        if (bytes.size != FIELD_SIZE * 2) {
            throw ValueException("An EC point is ${bytes.size} bytes, expected ${FIELD_SIZE * 2}")
        }
        val point = EcPoint.of(
            fromBytes(bytes.copyOfRange(0, FIELD_SIZE)),
            fromBytes(bytes.copyOfRange(FIELD_SIZE, FIELD_SIZE * 2)),
        )
        if (!isOnCurve(point)) throw ValueException("EC point is not on the P-256 curve")
        return point
    }

    fun isOnCurve(point: EcPoint): Boolean {
        if (point.isInfinity) return true
        if (point.x.signum() < 0 || point.x >= P) return false
        if (point.y.signum() < 0 || point.y >= P) return false
        val lhs = (point.y * point.y).mod(P)
        val rhs = (point.x * point.x * point.x - point.x * THREE + B).mod(P)
        return lhs == rhs
    }

    fun negate(point: EcPoint): EcPoint = if (point.isInfinity) point else EcPoint.of(point.x, (P - point.y).mod(P))

    fun add(a: EcPoint, b: EcPoint): EcPoint = toAffine(addJacobian(toJacobian(a), toJacobian(b)))

    fun subtract(a: EcPoint, b: EcPoint): EcPoint = add(a, negate(b))

    /**
     * scalar * point, by left-to-right double-and-add.
     *
     * @throws ValueException if [scalar] is outside the range 1 until n
     */
    fun scalarMultiply(scalar: BigInteger, point: EcPoint): EcPoint {
        if (scalar.signum() <= 0 || scalar >= N) throw ValueException("EC scalar is out of range")
        if (point.isInfinity) return EcPoint.INFINITY

        var result = JacobianPoint.INFINITY
        val base = toJacobian(point)
        for (bit in scalar.bitLength() - 1 downTo 0) {
            result = doubleJacobian(result)
            if (scalar.bitAt(bit.toLong())) result = addJacobian(result, base)
        }
        return toAffine(result)
    }

    /** The public point for a private scalar. */
    fun publicPoint(scalar: BigInteger): EcPoint = scalarMultiply(scalar, G)

    /** Jacobian projective coordinates; affine is (X/Z^2, Y/Z^3). */
    private class JacobianPoint(val x: BigInteger, val y: BigInteger, val z: BigInteger) {
        companion object {
            val INFINITY = JacobianPoint(BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)
        }
    }

    private fun toJacobian(point: EcPoint): JacobianPoint =
        if (point.isInfinity) JacobianPoint.INFINITY else JacobianPoint(point.x, point.y, BigInteger.ONE)

    private fun toAffine(point: JacobianPoint): EcPoint {
        if (point.z.isZero()) return EcPoint.INFINITY
        val zInv = point.z.modInverse(P)
        val zInv2 = (zInv * zInv).mod(P)
        val zInv3 = (zInv2 * zInv).mod(P)
        return EcPoint.of((point.x * zInv2).mod(P), (point.y * zInv3).mod(P))
    }

    // EFD "dbl-2001-b", which folds in a = -3.
    private fun doubleJacobian(p: JacobianPoint): JacobianPoint {
        if (p.z.isZero() || p.y.isZero()) return JacobianPoint.INFINITY

        val yy = (p.y * p.y).mod(P)
        val zz = (p.z * p.z).mod(P)
        val a = (p.x * yy * FOUR).mod(P)
        val b = (yy * yy * EIGHT).mod(P)
        val c = ((p.x - zz) * (p.x + zz) * THREE).mod(P)
        val d = (c * c - a * TWO).mod(P)

        return JacobianPoint(
            x = d,
            y = (c * (a - d) - b).mod(P),
            z = (p.y * p.z * TWO).mod(P),
        )
    }

    // EFD "add-2007-bl".
    private fun addJacobian(p: JacobianPoint, q: JacobianPoint): JacobianPoint {
        if (p.z.isZero()) return q
        if (q.z.isZero()) return p

        val z1z1 = (p.z * p.z).mod(P)
        val z2z2 = (q.z * q.z).mod(P)
        val u1 = (p.x * z2z2).mod(P)
        val u2 = (q.x * z1z1).mod(P)
        val s1 = (p.y * q.z * z2z2).mod(P)
        val s2 = (q.y * p.z * z1z1).mod(P)

        if (u1 == u2) {
            return if (s1 == s2) doubleJacobian(p) else JacobianPoint.INFINITY
        }

        val h = (u2 - u1).mod(P)
        val i = (h * TWO * (h * TWO)).mod(P)
        val j = (h * i).mod(P)
        val r = ((s2 - s1) * TWO).mod(P)
        val v = (u1 * i).mod(P)
        val x3 = (r * r - j - v * TWO).mod(P)

        return JacobianPoint(
            x = x3,
            y = (r * (v - x3) - s1 * j * TWO).mod(P),
            z = (((p.z + q.z) * (p.z + q.z) - z1z1 - z2z2) * h).mod(P),
        )
    }
}
