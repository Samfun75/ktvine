package org.samfun.ktvine

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import kotlinx.coroutines.test.runTest
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.crypto.aesCbcEncryptNoPadding
import org.samfun.ktvine.crypto.hmacSha256
import org.samfun.ktvine.crypto.pkcs7Pad
import org.samfun.ktvine.crypto.rsaOaepEncrypt
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.License
import org.samfun.ktvine.proto.LicenseIdentification
import org.samfun.ktvine.proto.LicenseRequest
import org.samfun.ktvine.proto.SignedDrmCertificate
import org.samfun.ktvine.proto.SignedMessage
import org.samfun.ktvine.proto.WidevinePsshData
import org.samfun.ktvine.utils.SignatureMismatchException
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Exercises the whole license exchange offline, against a throwaway device.
 *
 * The live proxy test covers the same ground but needs network access and the real device
 * fixture, so it runs nowhere by default. This one runs everywhere, including native.
 *
 * The response is assembled here the way a license server would: wrap a session key to the
 * device's public key, derive the ladder, encrypt the content keys under it and sign with
 * the server MAC key. The ladder itself is pinned independently by [CdmDerivationTest], so
 * this test is not merely agreeing with itself about the derivation.
 */
@OptIn(DelicateCryptographyApi::class)
class CdmOfflineLicenseTest {

    private val contentKid = Uuid.parse("11111111-2222-3333-4444-555555555555")
    private val contentKey = ByteArray(16) { (0xA0 + it).toByte() }
    private val keyIv = ByteArray(16) { (it * 7).toByte() }

    private class ThrowawayDevice(val device: Device, val publicKeyDer: ByteArray)

    /** A structurally valid device with a real RSA key, but nothing provisioned by Google. */
    private suspend fun throwawayDevice(): ThrowawayDevice {
        val rsa = CryptographyProvider.Default.get(RSA.PSS)
        val keyPair = rsa.keyPairGenerator(2048.bits, SHA1).generateKey()
        val privateKeyDer = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.DER.PKCS1)
        val publicKeyDer = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.DER.PKCS1)

        val drm = DrmCertificate(system_id = 4464, public_key = publicKeyDer.toByteString()).encode()
        val signed = SignedDrmCertificate(drm_certificate = drm.toByteString()).encode()
        val clientId = ClientIdentification(token = signed.toByteString())

        val wvd = Device.buildWvdV2(DeviceTypes.ANDROID, 3, privateKeyDer, clientId.encode())
        return ThrowawayDevice(Device.loads(wvd), publicKeyDer)
    }

    private fun pssh(): PSSH = PSSH.new(
        systemId = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"),
        initData = WidevinePsshData(key_ids = listOf(contentKid.toByteArray().toByteString())),
    )

    /** The request id a server would quote back in `License.id`. */
    private fun requestIdOf(challenge: ByteArray): ByteString {
        val request = LicenseRequest.ADAPTER.decode(SignedMessage.ADAPTER.decode(challenge).msg!!)
        val contentId = request.content_id!!
        return contentId.widevine_pssh_data?.request_id
            ?: contentId.existing_license!!.license_id!!.request_id!!
    }

    /** Build the response a license server would return for [challenge]. */
    private suspend fun issueLicense(
        cdm: Cdm,
        device: ThrowawayDevice,
        challenge: ByteArray,
        tamperWithSignature: Boolean = false,
        policy: License.Policy? = null,
    ): ByteArray {
        val signedRequest = SignedMessage.ADAPTER.decode(challenge)
        val requestBytes = signedRequest.msg!!.toByteArray()

        val sessionKey = ByteArray(16) { (it * 11 + 3).toByte() }
        val wrappedSessionKey = rsaOaepEncrypt(device.publicKeyDer, sessionKey)

        val (encContext, macContext) = cdm.deriveContext(requestBytes)
        val (encKey, macKeyServer, _) = cdm.deriveKeys(encContext, macContext, sessionKey)

        val encryptedKey = aesCbcEncryptNoPadding(encKey, keyIv, pkcs7Pad(contentKey))

        val license = License(
            id = LicenseIdentification(request_id = requestIdOf(challenge)),
            policy = policy,
            key = listOf(
                License.KeyContainer(
                    id = contentKid.toByteArray().toByteString(),
                    iv = keyIv.toByteString(),
                    key = encryptedKey.toByteString(),
                    type = License.KeyContainer.KeyType.CONTENT,
                ),
            ),
        ).encode()

        val signature = hmacSha256(macKeyServer, license).let {
            if (tamperWithSignature) it.copyOf().also { copy -> copy[0] = (copy[0] + 1).toByte() } else it
        }

        return SignedMessage(
            type = SignedMessage.MessageType.LICENSE,
            msg = license.toByteString(),
            signature = signature.toByteString(),
            session_key = wrappedSessionKey.toByteString(),
        ).encode()
    }

    @Test
    fun `test a full offline exchange recovers the content key`() = runTest {
        val device = throwawayDevice()
        val cdm = Cdm.fromDevice(device.device)
        val sessionId = cdm.open()

        val challenge = cdm.getLicenseChallenge(sessionId, pssh(), privacyMode = false)
        val response = issueLicense(cdm, device, challenge)

        cdm.parseLicense(sessionId, response)

        val keys = cdm.getKeys(sessionId)
        assertEquals(1, keys.size, "expected exactly the one content key")
        assertEquals(contentKid, keys[0].kid)
        assertEquals(License.KeyContainer.KeyType.CONTENT, keys[0].type)
        assertContentEquals(
            contentKey,
            keys[0].key,
            "recovered ${keys[0].key.toHexString()} instead of ${contentKey.toHexString()}",
        )

        // The decoded license itself must be retained, not just its keys.
        assertEquals(requestIdOf(challenge), cdm.getLicense(sessionId)!!.id!!.request_id)
    }

    @Test
    fun `test a tampered license is rejected`() = runTest {
        val device = throwawayDevice()
        val cdm = Cdm.fromDevice(device.device)
        val sessionId = cdm.open()

        val challenge = cdm.getLicenseChallenge(sessionId, pssh(), privacyMode = false)
        val response = issueLicense(cdm, device, challenge, tamperWithSignature = true)

        assertFailsWith<SignatureMismatchException> { cdm.parseLicense(sessionId, response) }
        assertTrue(cdm.getKeys(sessionId).isEmpty(), "a rejected license must not load keys")
    }

    @Test
    fun `test a license for another session's request is rejected`() = runTest {
        val device = throwawayDevice()
        val cdm = Cdm.fromDevice(device.device)

        val first = cdm.open()
        val second = cdm.open()

        val challenge = cdm.getLicenseChallenge(first, pssh(), privacyMode = false)
        val response = issueLicense(cdm, device, challenge)

        // The context is stored per session, keyed by request id.
        assertFailsWith<org.samfun.ktvine.utils.InvalidContextException> {
            cdm.parseLicense(second, response)
        }
    }

    @Test
    fun `test a renewal exchange completes and refreshes the keys`() = runTest {
        val device = throwawayDevice()
        val cdm = Cdm.fromDevice(device.device)
        val sessionId = cdm.open()

        val challenge = cdm.getLicenseChallenge(sessionId, pssh(), privacyMode = false)
        val renewable = License.Policy(can_renew = true)
        cdm.parseLicense(sessionId, issueLicense(cdm, device, challenge, policy = renewable))

        val originalRequestId = requestIdOf(challenge)

        val renewal = cdm.getLicenseChallenge(
            sessionId,
            pssh(),
            privacyMode = false,
            requestType = LicenseRequest.RequestType.RENEWAL,
        )

        val renewalRequest = LicenseRequest.ADAPTER.decode(SignedMessage.ADAPTER.decode(renewal).msg!!)
        assertEquals(LicenseRequest.RequestType.RENEWAL, renewalRequest.type)
        assertEquals(originalRequestId, renewalRequest.content_id!!.existing_license!!.license_id!!.request_id)

        // Keyed on a fresh id instead, this threw InvalidContextException.
        cdm.parseLicense(sessionId, issueLicense(cdm, device, renewal, policy = renewable))

        val keys = cdm.getKeys(sessionId)
        assertEquals(1, keys.size)
        assertContentEquals(contentKey, keys[0].key)
    }

    @Test
    fun `test a renewal is refused when the policy forbids it`() = runTest {
        val device = throwawayDevice()
        val cdm = Cdm.fromDevice(device.device)
        val sessionId = cdm.open()

        val challenge = cdm.getLicenseChallenge(sessionId, pssh(), privacyMode = false)
        cdm.parseLicense(sessionId, issueLicense(cdm, device, challenge, policy = License.Policy(can_renew = false)))

        assertFailsWith<org.samfun.ktvine.utils.ValueException> {
            cdm.getLicenseChallenge(
                sessionId,
                pssh(),
                privacyMode = false,
                requestType = LicenseRequest.RequestType.RENEWAL,
            )
        }
    }

    @Test
    fun `test a license cannot be replayed onto the same session twice`() = runTest {
        val device = throwawayDevice()
        val cdm = Cdm.fromDevice(device.device)
        val sessionId = cdm.open()

        val challenge = cdm.getLicenseChallenge(sessionId, pssh(), privacyMode = false)
        val response = issueLicense(cdm, device, challenge)

        cdm.parseLicense(sessionId, response)
        // parseLicense consumes the stored context, so a second attempt has nothing to use.
        assertFailsWith<org.samfun.ktvine.utils.InvalidContextException> {
            cdm.parseLicense(sessionId, response)
        }
    }
}
