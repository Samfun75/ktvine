package org.samfun.ktprd

import com.ionspin.kotlin.bignum.integer.BigInteger
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.crypto.P256
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Cross-checks ktprd's hand-written ECDSA against cryptography-kotlin's provider.
 *
 * The RFC 6979 vectors prove the signatures are the published ones; this proves an entirely
 * separate implementation accepts them, so a shared misreading of the spec cannot pass both.
 * It is JVM-only because it needs a provider that can import a raw public key, which the Apple
 * provider cannot.
 */
class EcdsaProviderCrossJvmTest {

    private suspend fun providerVerifies(
        publicKeyBytes: ByteArray,
        message: ByteArray,
        signature: ByteArray,
    ): Boolean = CryptographyProvider.Default
        .get(ECDSA)
        .publicKeyDecoder(EC.Curve.P256)
        .decodeFromByteArray(EC.PublicKey.Format.RAW, byteArrayOf(0x04) + publicKeyBytes)
        .signatureVerifier(SHA256, ECDSA.SignatureFormat.RAW)
        .tryVerifySignature(message, signature)

    @Test
    fun `test the provider accepts signatures ktprd produced`() = runTest {
        val message = "a PlayReady license challenge".encodeToByteArray()

        for (seed in listOf("1", "112233445566778899", "31337", "7")) {
            val scalar = BigInteger.parseString(seed, 10)
            val signature = Ecdsa.sign(scalar, message)
            assertTrue(
                providerVerifies(P256.publicPoint(scalar).encode(), message, signature),
                "provider rejected a ktprd signature under scalar $seed",
            )
        }
    }

    @Test
    fun `test the provider rejects a signature ktprd also rejects`() = runTest {
        val scalar = BigInteger.parseString("112233445566778899", 10)
        val publicKey = P256.publicPoint(scalar).encode()
        val message = "a PlayReady license challenge".encodeToByteArray()

        val signature = Ecdsa.sign(scalar, message)
        signature[40] = (signature[40].toInt() xor 0x20).toByte()

        assertFalse(providerVerifies(publicKey, message, signature))
        assertFalse(Ecdsa.verify(publicKey, message, signature))
    }

    @Test
    fun `test ktprd accepts signatures the provider produced`() = runTest {
        val message = "a PlayReady license challenge".encodeToByteArray()
        val keyPair = CryptographyProvider.Default
            .get(ECDSA)
            .keyPairGenerator(EC.Curve.P256)
            .generateKey()

        val signature = keyPair.privateKey
            .signatureGenerator(SHA256, ECDSA.SignatureFormat.RAW)
            .generateSignature(message)

        // The provider emits 0x04 || X || Y; ktprd's structures carry the bare X || Y.
        val publicKey = keyPair.publicKey.encodeToByteArray(EC.PublicKey.Format.RAW).copyOfRange(1, 65)

        assertTrue(Ecdsa.verify(publicKey, message, signature))
    }
}
