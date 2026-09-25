package org.samfun.ktvine

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256
import kotlinx.coroutines.test.runTest
import okio.ByteString.Companion.decodeHex
import org.samfun.ktvine.crypto.aesCbcDecrypt
import org.samfun.ktvine.crypto.aesCbcEncryptNoPadding
import org.samfun.ktvine.crypto.hmacSha256
import org.samfun.ktvine.crypto.rsaOaepDecrypt
import org.samfun.ktvine.crypto.rsaOaepEncrypt
import org.samfun.ktvine.crypto.rsaPssSignSha1
import org.samfun.ktvine.crypto.rsaPssVerifySha1
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Default resolves to a different provider per target, so a missing algorithm only fails at runtime there. */
@OptIn(DelicateCryptographyApi::class)
class CryptoProviderTest {

    private val provider = CryptographyProvider.Default

    private fun hex(value: String): ByteArray = value.decodeHex().toByteArray()

    private class RsaKeyPair(val privateKeyDer: ByteArray, val publicKeyDer: ByteArray)

    private suspend fun rsaKeyPair(): RsaKeyPair {
        val keyPair = provider.get(RSA.OAEP).keyPairGenerator(2048.bits, SHA1).generateKey()
        return RsaKeyPair(
            keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.DER.PKCS1),
            keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.DER.PKCS1),
        )
    }

    @Test
    fun `test RSA-PSS SHA-1 signs and verifies`() = runTest {
        val key = rsaKeyPair()
        val message = "license request".encodeToByteArray()

        val signature = rsaPssSignSha1(key.privateKeyDer, message)

        assertEquals(256, signature.size)
        assertTrue(rsaPssVerifySha1(key.publicKeyDer, message, signature))
        assertFalse(rsaPssVerifySha1(key.publicKeyDer, "tampered".encodeToByteArray(), signature))
    }

    @Test
    fun `test RSA-OAEP SHA-1 round trips`() = runTest {
        val key = rsaKeyPair()
        val sessionKey = ByteArray(16) { it.toByte() }

        val wrapped = rsaOaepEncrypt(key.publicKeyDer, sessionKey)

        assertContentEquals(sessionKey, rsaOaepDecrypt(key.privateKeyDer, wrapped))
    }

    @Test
    fun `test AES-CBC matches the SP 800-38A vector`() = runTest {
        val key = hex("2b7e151628aed2a6abf7158809cf4f3c")
        val iv = hex("000102030405060708090a0b0c0d0e0f")
        val plaintext = hex("6bc1bee22e409f96e93d7e117393172a")

        val ciphertext = aesCbcEncryptNoPadding(key, iv, plaintext)

        assertEquals("7649abac8119b246cee98e9b12e9197d", ciphertext.toHexString())
        assertContentEquals(plaintext, aesCbcDecrypt(key, iv, ciphertext))
    }

    @Test
    fun `test HMAC-SHA256 matches the RFC 4231 vector`() = runTest {
        val mac = hmacSha256("Jefe".encodeToByteArray(), "what do ya want for nothing?".encodeToByteArray())

        assertEquals("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", mac.toHexString())
    }

    // ktprd's PrCrypto asks the same Default provider for these, and it has no device suite of its own.
    @Test
    fun `test AES-ECB matches the SP 800-38A vector`() = runTest {
        val cipher = provider.get(AES.ECB).keyDecoder()
            .decodeFromByteArray(AES.Key.Format.RAW, hex("2b7e151628aed2a6abf7158809cf4f3c"))
            .cipher(padding = false)

        val ciphertext = cipher.encrypt(hex("6bc1bee22e409f96e93d7e117393172a"))

        assertEquals("3ad77bb40d7a3660a89ecaf32466ef97", ciphertext.toHexString())
    }

    @Test
    fun `test SHA digests match the FIPS 180 vectors`() = runTest {
        val abc = "abc".encodeToByteArray()

        assertEquals("a9993e364706816aba3e25717850c26c9cd0d89d", provider.get(SHA1).hasher().hash(abc).toHexString())
        assertEquals(
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            provider.get(SHA256).hasher().hash(abc).toHexString(),
        )
    }
}
