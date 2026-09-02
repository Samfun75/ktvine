package org.samfun.ktvine

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import kotlinx.coroutines.runBlocking
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.crypto.rsaPssSignSha1
import org.samfun.ktvine.crypto.rsaPssVerifySha1
import org.samfun.ktvine.proto.SignedMessage
import org.samfun.ktvine.utils.InvalidContextException
import org.samfun.ktvine.utils.InvalidLicenseMessageException
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContains
import kotlin.test.assertFailsWith
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

    private fun cdmOrSkip(): Cdm? {
        val data = TestFixtures.orSkip("device/widevine/google_avd.wvd") ?: return null
        return Cdm.fromDevice(Device.loads(data))
    }

    @Test
    fun `test error response is reported with its payload`() {
        runBlocking {
            val cdm = cdmOrSkip() ?: return@runBlocking
            val sessionId = cdm.open()
            val errorResponse = SignedMessage(
                type = SignedMessage.MessageType.ERROR_RESPONSE,
                msg = byteArrayOf(0x08, 0x02).toByteString(),
            ).encode()

            val failure = assertFailsWith<InvalidLicenseMessageException> {
                cdm.parseLicense(sessionId, errorResponse)
            }
            assertContains(failure.message!!, "ERROR_RESPONSE")
            assertContains(failure.message!!, "0802", message = "payload should be reported verbatim")
        }
    }

    @Test
    fun `test parsing a license without a prior challenge reports missing context`() {
        runBlocking {
            val cdm = cdmOrSkip() ?: return@runBlocking
            val sessionId = cdm.open()
            val license = SignedMessage(
                type = SignedMessage.MessageType.LICENSE,
                msg = org.samfun.ktvine.proto.License(
                    id = org.samfun.ktvine.proto.LicenseIdentification(
                        request_id = byteArrayOf(1, 2, 3, 4).toByteString(),
                    ),
                ).encode().toByteString(),
            ).encode()

            assertFailsWith<InvalidContextException> { cdm.parseLicense(sessionId, license) }
        }
    }

    @Test
    fun `test empty license message is rejected`() {
        runBlocking {
            val cdm = cdmOrSkip() ?: return@runBlocking
            val sessionId = cdm.open()
            assertFailsWith<InvalidLicenseMessageException> { cdm.parseLicense(sessionId, ByteArray(0)) }
        }
    }
}
