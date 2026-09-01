package org.samfun.ktvine.serve

import dev.whyoleg.cryptography.BinarySize.Companion.bits
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import okio.ByteString.Companion.toByteString
import org.samfun.ktvine.core.Device
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.proto.DrmCertificate
import org.samfun.ktvine.proto.SignedDrmCertificate
import org.samfun.ktvine.proto.WidevinePsshData
import kotlin.uuid.Uuid

/** A structurally valid device with a real RSA key, provisioned by nobody. */
@OptIn(DelicateCryptographyApi::class)
object TestDevice {

    const val SYSTEM_ID: Int = 4464
    const val SECURITY_LEVEL: Int = 3

    private val lock = Mutex()
    private var cached: Device? = null

    /** Generated once: a 2048-bit key pair per test would dominate the run time. */
    suspend fun make(): Device = lock.withLock {
        cached ?: build().also { cached = it }
    }

    private suspend fun build(): Device {
        val rsa = CryptographyProvider.Default.get(RSA.PSS)
        val keyPair = rsa.keyPairGenerator(2048.bits, SHA1).generateKey()
        val privateKeyDer = keyPair.privateKey.encodeToByteArray(RSA.PrivateKey.Format.DER.PKCS1)
        val publicKeyDer = keyPair.publicKey.encodeToByteArray(RSA.PublicKey.Format.DER.PKCS1)

        val drm = DrmCertificate(system_id = SYSTEM_ID, public_key = publicKeyDer.toByteString()).encode()
        val signed = SignedDrmCertificate(drm_certificate = drm.toByteString()).encode()
        val clientId = ClientIdentification(token = signed.toByteString())

        return Device.loads(
            Device.buildWvdV2(DeviceTypes.ANDROID, SECURITY_LEVEL, privateKeyDer, clientId.encode()),
        )
    }

    val KID: Uuid = Uuid.parse("11111111-2222-3333-4444-555555555555")

    fun pssh(): PSSH = PSSH.new(
        systemId = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"),
        initData = WidevinePsshData(key_ids = listOf(KID.toByteArray().toByteString())),
    )

    val PSSH_B64: String get() = pssh().exportBase64()
}
