package org.samfun.ktprd

import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyCipherType
import org.samfun.ktprd.core.PlayreadyKeyType
import org.samfun.ktprd.crypto.ElGamal
import org.samfun.ktprd.crypto.P256
import org.samfun.ktprd.utils.ByteWriter
import org.samfun.ktprd.utils.InvalidXmrLicenseException
import org.samfun.ktprd.utils.XmrSignatureException
import org.samfun.ktprd.xmr.XmrLicense
import org.samfun.ktprd.xmr.XmrObjectType
import org.samfun.ktvine.crypto.aesCmac
import org.samfun.ktvine.utils.toHexString
import org.samfun.ktvine.utils.toLittleEndianByteArray
import org.samfun.ktvine.utils.uuidFromLittleEndian
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Builds an XMR license the way a server would and reads the content key back out.
 *
 * A real license cannot be checked in — one is bound to a real device's private key — so the
 * exchange is reconstructed here instead. It runs on every target, which is what makes the
 * ElGamal and CMAC paths verified on iOS and Linux rather than only on the JVM.
 */
class XmrLicenseTest {

    private val deviceKey = EccKey.loads(P256.toFixed32(ElGamal.randomScalar()))
    private val kid = Uuid.parse("01234567-89ab-cdef-0123-456789abcdef")

    /** Key material is always the X of some curve point, so it is generated as one. */
    private fun keyMaterial(): Pair<ByteArray, ByteArray> {
        val scalar = ElGamal.randomScalar()
        val point = P256.publicPoint(scalar)
        return P256.toFixed32(point.x) to ElGamal.encrypt(point, P256.decodePoint(deviceKey.publicBytes))
    }

    private fun xmrObject(type: XmrObjectType, body: ByteArray, flags: Int = 1): ByteArray = ByteWriter()
        .u16(flags)
        .u16(type.value)
        .u32(body.size + 8)
        .bytes(body)
        .toByteArray()

    private fun container(type: XmrObjectType, vararg children: ByteArray): ByteArray {
        val body = children.fold(ByteWriter()) { writer, child -> writer.bytes(child) }.toByteArray()
        return xmrObject(type, body, flags = 2)
    }

    private suspend fun buildLicense(
        encryptedKey: ByteArray,
        integrityKey: ByteArray,
        keyType: PlayreadyKeyType = PlayreadyKeyType.AES_128_CTR,
        cipherType: PlayreadyCipherType = PlayreadyCipherType.ECC_256,
        deviceKeyBytes: ByteArray = deviceKey.publicBytes,
    ): ByteArray {
        val eccKeyObject = xmrObject(
            XmrObjectType.ECC_DEVICE_KEY,
            ByteWriter().u16(1).u16(deviceKeyBytes.size).bytes(deviceKeyBytes).toByteArray(),
        )
        val contentKeyObject = xmrObject(
            XmrObjectType.CONTENT_KEY,
            ByteWriter()
                .bytes(kid.toLittleEndianByteArray())
                .u16(keyType.value)
                .u16(cipherType.value)
                .u16(encryptedKey.size)
                .bytes(encryptedKey)
                .toByteArray(),
        )

        val prefix = ByteWriter()
            .bytes(byteArrayOf('X'.code.toByte(), 'M'.code.toByte(), 'R'.code.toByte(), 0))
            .u32(1)
            .bytes(ByteArray(16) { it.toByte() })
            .bytes(
                container(
                    XmrObjectType.OUTER_CONTAINER,
                    container(XmrObjectType.KEY_MATERIAL_CONTAINER, eccKeyObject, contentKeyObject),
                ),
            )
            .toByteArray()

        val signature = aesCmac(integrityKey, prefix)
        return prefix + xmrObject(
            XmrObjectType.SIGNATURE,
            ByteWriter().u16(1).u16(signature.size).bytes(signature).toByteArray(),
        )
    }

    @Test
    fun `test a license yields the content key it was built around`() = runTest {
        val (material, encrypted) = keyMaterial()
        val license = XmrLicense.loads(buildLicense(encrypted, material.copyOfRange(0, 16)))

        assertEquals(1L, license.version)
        assertFalse(license.isScalable)
        assertContentEquals(deviceKey.publicBytes, license.deviceKey)

        val key = license.contentKey(deviceKey)
        assertEquals(kid, key.kid)
        assertEquals(PlayreadyKeyType.AES_128_CTR, key.keyType)
        assertEquals(PlayreadyCipherType.ECC_256, key.cipherType)
        assertEquals(material.copyOfRange(16, 32).toHexString(), key.key.toHexString())
    }

    @Test
    fun `test the key id is read as a little endian GUID`() = runTest {
        val (material, encrypted) = keyMaterial()
        val license = XmrLicense.loads(buildLicense(encrypted, material.copyOfRange(0, 16)))

        // The object stores the GUID byte-swapped; reading it big-endian would give a different id
        // from the one the manifest advertises.
        assertEquals(kid, license.contentKey?.kid)
        assertEquals(kid, kid.toLittleEndianByteArray().uuidFromLittleEndian())
    }

    @Test
    fun `test a license issued to another device is refused`() = runTest {
        val other = EccKey.generate()
        val (material, encrypted) = keyMaterial()
        val license = XmrLicense.loads(
            buildLicense(encrypted, material.copyOfRange(0, 16), deviceKeyBytes = other.publicBytes),
        )

        assertFailsWith<InvalidXmrLicenseException> { license.contentKey(deviceKey) }
    }

    @Test
    fun `test a tampered license fails its integrity signature`() = runTest {
        val (material, encrypted) = keyMaterial()
        val raw = buildLicense(encrypted, material.copyOfRange(0, 16))

        // Flip a byte inside the rights id, which the CMAC covers but no accessor validates.
        raw[10] = (raw[10].toInt() xor 0xFF).toByte()

        assertFailsWith<XmrSignatureException> { XmrLicense.loads(raw).contentKey(deviceKey) }
    }

    @Test
    fun `test a license signed with the wrong integrity key is refused`() = runTest {
        val (_, encrypted) = keyMaterial()
        val license = XmrLicense.loads(buildLicense(encrypted, ByteArray(16) { 0x5A }))

        assertFailsWith<XmrSignatureException> { license.contentKey(deviceKey) }
    }

    @Test
    fun `test an unsupported cipher type is refused`() = runTest {
        val (material, encrypted) = keyMaterial()
        val license = XmrLicense.loads(
            buildLicense(encrypted, material.copyOfRange(0, 16), cipherType = PlayreadyCipherType.RSA_1024),
        )

        assertFailsWith<InvalidXmrLicenseException> { license.contentKey(deviceKey) }
    }

    @Test
    fun `test objects nested inside containers are found`() = runTest {
        val (material, encrypted) = keyMaterial()
        val license = XmrLicense.loads(buildLicense(encrypted, material.copyOfRange(0, 16)))

        // Both the key material and the device key sit two containers deep.
        assertTrue(license.objects.size >= 2)
        assertContentEquals(deviceKey.publicBytes, license.deviceKey)
    }

    @Test
    fun `test data without the XMR magic is rejected`() {
        assertFailsWith<InvalidXmrLicenseException> { XmrLicense.loads(byteArrayOf(1, 2, 3, 4, 5, 6, 7, 8)) }
    }

    @Test
    fun `test an object claiming a length below its own header is rejected`() {
        val raw = ByteWriter()
            .bytes(byteArrayOf('X'.code.toByte(), 'M'.code.toByte(), 'R'.code.toByte(), 0))
            .u32(1)
            .bytes(ByteArray(16))
            .u16(1).u16(XmrObjectType.CONTENT_KEY.value).u32(4)
            .toByteArray()

        assertFailsWith<InvalidXmrLicenseException> { XmrLicense.loads(raw) }
    }
}
