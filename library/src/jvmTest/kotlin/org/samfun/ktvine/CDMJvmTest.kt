package org.samfun.ktvine

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import kotlinx.coroutines.runBlocking
import org.samfun.ktvine.crypto.rsaPssSignSha1
import org.samfun.ktvine.crypto.rsaPssVerifySha1
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertTrue

@OptIn(DelicateCryptographyApi::class)
class CDMJvmTest {

    @Test
    fun `test sign with rsa pss sha1`() {
        runBlocking {
            val rsa = CryptographyProvider.Default.get(RSA.PSS)
            val keyPair = rsa.keyPairGenerator(2048.bits, SHA1).generateKey()
            val private = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.DER.PKCS1)
            val public = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.DER.PKCS1)

            val data = ByteArray(32) { SecureRandom().nextInt(0, 256).toByte() }
            val signature = rsaPssSignSha1(private, data)
            val verified = rsaPssVerifySha1(public, data, signature)
            assertTrue(verified, "Signature verification failed")
        }
    }
}
