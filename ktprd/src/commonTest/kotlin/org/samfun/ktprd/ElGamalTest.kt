package org.samfun.ktprd

import com.ionspin.kotlin.bignum.integer.BigInteger
import org.samfun.ktprd.crypto.ElGamal
import org.samfun.ktprd.crypto.P256
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class ElGamalTest {

    private val privateScalar = BigInteger.parseString("112233445566778899", 10)
    private val publicPoint = P256.publicPoint(privateScalar)

    @Test
    fun `test decrypting a hand built ciphertext recovers the message point`() {
        // Built with P256 alone rather than with ElGamal.encrypt, so decrypt is checked against
        // the definition of the scheme and not merely against our own encryptor.
        val message = P256.publicPoint(BigInteger.parseString("42", 10))
        val ephemeral = BigInteger.parseString("7", 10)

        val c1 = P256.scalarMultiply(ephemeral, P256.G)
        val c2 = P256.add(message, P256.scalarMultiply(ephemeral, publicPoint))

        val recovered = ElGamal.decrypt(c1.encode() + c2.encode(), privateScalar)
        assertEquals(P256.toFixed32(message.x).toHexString(), recovered.toHexString())
    }

    @Test
    fun `test encrypt then decrypt round trips`() {
        val message = P256.publicPoint(BigInteger.parseString("31337", 10))
        val ciphertext = ElGamal.encrypt(message, publicPoint)

        assertEquals(ElGamal.CIPHERTEXT_SIZE, ciphertext.size)
        assertEquals(
            P256.toFixed32(message.x).toHexString(),
            ElGamal.decrypt(ciphertext, privateScalar).toHexString(),
        )
    }

    @Test
    fun `test each encryption draws a fresh ephemeral scalar`() {
        val message = P256.publicPoint(BigInteger.parseString("31337", 10))
        assertNotEquals(
            ElGamal.encrypt(message, publicPoint).toHexString(),
            ElGamal.encrypt(message, publicPoint).toHexString(),
        )
    }

    @Test
    fun `test decrypting with the wrong key gives a different point`() {
        val message = P256.publicPoint(BigInteger.parseString("31337", 10))
        val ciphertext = ElGamal.encrypt(message, publicPoint)
        assertNotEquals(
            P256.toFixed32(message.x).toHexString(),
            ElGamal.decrypt(ciphertext, BigInteger.parseString("998877665544332211", 10)).toHexString(),
        )
    }

    @Test
    fun `test a ciphertext of the wrong length is rejected`() {
        assertFailsWith<ValueException> { ElGamal.decrypt(ByteArray(127), privateScalar) }
    }
}
