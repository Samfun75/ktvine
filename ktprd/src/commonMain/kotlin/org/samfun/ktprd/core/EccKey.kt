package org.samfun.ktprd.core

import com.ionspin.kotlin.bignum.integer.BigInteger
import org.samfun.ktprd.crypto.ElGamal
import org.samfun.ktprd.crypto.P256
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.toHexString
import kotlin.io.encoding.Base64

/**
 * A P-256 key pair, in the shape PlayReady stores them.
 *
 * A device's group, signing and encryption keys are all of this form. On disk they appear as
 * `zgpriv.dat`, `zprivsig.dat` and `zprivencr.dat`, and inside a `.prd` as fixed 96-byte slots.
 *
 * The public point is always **derived** from the private scalar rather than read from the blob,
 * so a `.prd` whose stored public half disagrees with its private half cannot produce a key pair
 * that fails silently later.
 */
public class EccKey private constructor(
    private val scalarBytes: ByteArray,
    /** The public point as 64 bytes, `X` then `Y`, big-endian and without a `0x04` prefix. */
    public val publicBytes: ByteArray,
) {
    /** The private scalar as 32 big-endian bytes. */
    public val privateBytes: ByteArray get() = scalarBytes.copyOf()

    internal val scalar: BigInteger get() = P256.fromBytes(scalarBytes)

    /**
     * Serialize as `d‖X‖Y` (96 bytes), or just `d` (32 bytes) when [privateOnly] is set.
     *
     * The 32-byte form is what `zgpriv.dat` holds; the 96-byte form is what a `.prd` slot holds.
     */
    public fun dumps(privateOnly: Boolean = false): ByteArray =
        if (privateOnly) privateBytes else privateBytes + publicBytes

    override fun toString(): String = "EccKey(public=${publicBytes.toHexString()})"

    override fun equals(other: Any?): Boolean = other is EccKey && scalarBytes.contentEquals(other.scalarBytes)

    override fun hashCode(): Int = scalarBytes.contentHashCode()

    public companion object {
        /** Bytes in the private scalar. */
        public const val PRIVATE_SIZE: Int = 32

        /** Bytes in the uncompressed public point. */
        public const val PUBLIC_SIZE: Int = 64

        /** Bytes in a full `d‖X‖Y` blob. */
        public const val BLOB_SIZE: Int = PRIVATE_SIZE + PUBLIC_SIZE

        /** A fresh key pair from the platform CSPRNG. */
        public fun generate(): EccKey = fromScalar(ElGamal.randomScalar())

        /**
         * Load a key from a 32-byte private scalar or a 96-byte `d‖X‖Y` blob.
         *
         * @throws ValueException if the blob is neither length, or the scalar is out of range
         */
        public fun loads(data: ByteArray): EccKey {
            if (data.size != PRIVATE_SIZE && data.size != BLOB_SIZE) {
                throw ValueException("An ECC key blob is ${data.size} bytes, expected $PRIVATE_SIZE or $BLOB_SIZE")
            }
            return fromScalar(P256.fromBytes(data.copyOf(PRIVATE_SIZE)))
        }

        /** Load a key from a Base64-encoded blob. */
        public fun loads(base64: String): EccKey = loads(
            try {
                Base64.decode(base64)
            } catch (e: Throwable) {
                throw ValueException("ECC key is not valid Base64, $e")
            },
        )

        internal fun fromScalar(scalar: BigInteger): EccKey {
            if (scalar.signum() <= 0 || scalar >= P256.N) throw ValueException("ECC private key is out of range")
            return EccKey(P256.toFixed32(scalar), P256.publicPoint(scalar).encode())
        }
    }
}
