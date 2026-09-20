@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd.xmr

import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyCipherType
import org.samfun.ktprd.core.PlayreadyKey
import org.samfun.ktprd.core.PlayreadyKeyType
import org.samfun.ktprd.crypto.ElGamal
import org.samfun.ktprd.crypto.aesEcbEncrypt
import org.samfun.ktprd.crypto.xor
import org.samfun.ktprd.utils.ByteReader
import org.samfun.ktprd.utils.InvalidXmrLicenseException
import org.samfun.ktprd.utils.XmrSignatureException
import org.samfun.ktvine.crypto.aesCmac
import org.samfun.ktvine.crypto.constantTimeEquals
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.uuidFromLittleEndian
import kotlin.io.encoding.Base64
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * One object in an XMR license's tree.
 *
 * A container carries [children]; a leaf carries [body]. Bodies stay raw and are decoded by the
 * accessors that understand them, because most object types are policy this CDM does not model.
 */
public class XmrObject internal constructor(
    public val flags: Int,
    public val type: XmrObjectType,
    public val body: ByteArray,
    public val children: List<XmrObject>,
    /** Offset of this object's header within the license, used to reconstruct the signed prefix. */
    internal val offset: Int,
) {
    internal val isContainer: Boolean get() = flags == CONTAINER_FLAG || flags == CONTAINER_WITH_MUST_UNDERSTAND_FLAG

    /** This object and everything beneath it, depth first. */
    internal fun walk(): Sequence<XmrObject> = sequence {
        yield(this@XmrObject)
        children.forEach { yieldAll(it.walk()) }
    }

    override fun toString(): String =
        if (isContainer) "XmrObject($type, ${children.size} children)" else "XmrObject($type, ${body.size} bytes)"

    internal companion object {
        const val HEADER_SIZE: Int = 8
        const val CONTAINER_FLAG: Int = 2
        const val CONTAINER_WITH_MUST_UNDERSTAND_FLAG: Int = 3
    }
}

/** The encrypted content-key object a license carries. */
public class XmrContentKey internal constructor(
    public val kid: Uuid,
    public val keyType: PlayreadyKeyType,
    public val cipherType: PlayreadyCipherType,
    public val encryptedKey: ByteArray,
)

/**
 * A parsed XMR license — the binary payload a PlayReady server returns inside its SOAP response.
 *
 * The source bytes are kept: the licence's integrity CMAC covers everything before its signature
 * object, and re-encoding a tree whose policy objects we deliberately do not model would not
 * reproduce those bytes.
 */
public class XmrLicense internal constructor(
    /** Exactly the bytes this license was parsed from. */
    public val raw: ByteArray,
    public val version: Long,
    public val rightsId: ByteArray,
    public val objects: List<XmrObject>,
) {
    private fun find(type: XmrObjectType): XmrObject? =
        objects.asSequence().flatMap { it.walk() }.firstOrNull { it.type == type }

    /** True when the license splits its key material across an auxiliary key — "scalable" licenses. */
    public val isScalable: Boolean get() = find(XmrObjectType.AUX_KEY) != null

    /** The public key of the device this license was issued to, as 64 bytes of `X‖Y`. */
    public val deviceKey: ByteArray?
        get() {
            val body = find(XmrObjectType.ECC_DEVICE_KEY)?.body ?: return null
            val reader = ByteReader(body)
            reader.u16("ECC device key curve type")
            val length = reader.u16("ECC device key length")
            return reader.bytes(length, "ECC device key")
        }

    public val contentKey: XmrContentKey?
        get() {
            val body = find(XmrObjectType.CONTENT_KEY)?.body ?: return null
            val reader = ByteReader(body)
            val kid = reader.bytes(16, "content key id")
            val keyType = reader.u16("content key type")
            val cipherType = reader.u16("content key cipher type")
            val length = reader.u16("content key length")
            return XmrContentKey(
                kid = kid.uuidFromLittleEndian(),
                keyType = PlayreadyKeyType.of(keyType),
                cipherType = PlayreadyCipherType.of(cipherType),
                encryptedKey = reader.bytes(length, "encrypted content key"),
            )
        }

    private val auxKeys: List<ByteArray>
        get() {
            val body = find(XmrObjectType.AUX_KEY)?.body ?: return emptyList()
            val reader = ByteReader(body)
            val count = reader.countOf(reader.u16("auxiliary key count").toLong(), "auxiliary keys")
            return List(count) {
                reader.u32("auxiliary key location")
                reader.bytes(16, "auxiliary key")
            }
        }

    /**
     * Decrypt the content key using the device's encryption key.
     *
     * The license encrypts a 32-byte block to the device: the first half is an integrity key that
     * authenticates the whole license, the second half is the content key. A scalable license
     * interleaves the two and wraps the real key behind an auxiliary-key derivation instead.
     *
     * @throws InvalidXmrLicenseException if the license is for another device, or uses a cipher
     *   this CDM has no key for
     * @throws XmrSignatureException if the license's integrity CMAC does not match
     */
    public suspend fun contentKey(encryptionKey: EccKey): PlayreadyKey {
        val licenseDeviceKey = deviceKey
            ?: throw InvalidXmrLicenseException("License carries no ECC device key object")
        if (!licenseDeviceKey.contentEquals(encryptionKey.publicBytes)) {
            throw InvalidXmrLicenseException("License was issued to a different device encryption key")
        }

        val container = contentKey
            ?: throw InvalidXmrLicenseException("License carries no content key object")

        if (container.cipherType !in SUPPORTED_CIPHERS) {
            throw InvalidXmrLicenseException("Content key cipher ${container.cipherType} is not an ECC-256 cipher")
        }

        if (container.encryptedKey.size < ElGamal.CIPHERTEXT_SIZE) {
            throw InvalidXmrLicenseException(
                "Encrypted content key is ${container.encryptedKey.size} bytes, " +
                    "expected at least ${ElGamal.CIPHERTEXT_SIZE}",
            )
        }

        // A scalable key appends an embedded license after the point pair; only the pair is ElGamal.
        val decrypted = try {
            ElGamal.decrypt(container.encryptedKey.copyOf(ElGamal.CIPHERTEXT_SIZE), encryptionKey.scalar)
        } catch (e: ValueException) {
            throw InvalidXmrLicenseException("Content key could not be decrypted, ${e.message}")
        }

        var integrityKey = decrypted.copyOfRange(0, 16)
        var contentKeyBytes = decrypted.copyOfRange(16, 32)

        if (isScalable) {
            integrityKey = ByteArray(16) { decrypted[it * 2] }
            contentKeyBytes = ByteArray(16) { decrypted[it * 2 + 1] }

            if (container.cipherType == PlayreadyCipherType.ECC_256_VIA_SYMMETRIC) {
                val leaf = unwrapEmbeddedLeaf(container.encryptedKey, contentKeyBytes)
                integrityKey = leaf.copyOfRange(0, 16)
                contentKeyBytes = leaf.copyOfRange(16, 32)
            }
        }

        verifyIntegrity(integrityKey)

        return PlayreadyKey(
            kid = container.kid,
            key = contentKeyBytes,
            keyType = container.keyType,
            cipherType = container.cipherType,
            keyLength = contentKeyBytes.size,
        )
    }

    /**
     * Peel the embedded leaf license a scalable `ECC_256_VIA_SYMMETRIC` key hides behind.
     *
     * The ElGamal step only yields the root key; the real content key sits in an embedded leaf
     * license wrapped under two keys derived from it.
     */
    private suspend fun unwrapEmbeddedLeaf(encryptedKey: ByteArray, rootKey: ByteArray): ByteArray {
        if (encryptedKey.size <= EMBEDDED_ROOT_SIZE) {
            throw InvalidXmrLicenseException(
                "A scalable content key needs more than $EMBEDDED_ROOT_SIZE bytes, got ${encryptedKey.size}",
            )
        }
        val auxKey = auxKeys.firstOrNull()
            ?: throw InvalidXmrLicenseException("A scalable license carries no auxiliary key")

        val embeddedRoot = encryptedKey.copyOf(EMBEDDED_ROOT_SIZE)
        var embeddedLeaf = encryptedKey.copyOfRange(EMBEDDED_ROOT_SIZE, encryptedKey.size)

        val contentKeyPrime = aesEcbEncrypt(rootKey, rootKey.xor(MAGIC_CONSTANT_ZERO))
        val uplinkXKey = aesEcbEncrypt(contentKeyPrime, auxKey)
        val secondaryKey = aesEcbEncrypt(rootKey, embeddedRoot.copyOfRange(EMBEDDED_ROOT_SIZE - 16, EMBEDDED_ROOT_SIZE))

        embeddedLeaf = aesEcbEncrypt(uplinkXKey, embeddedLeaf)
        embeddedLeaf = aesEcbEncrypt(secondaryKey, embeddedLeaf)

        if (embeddedLeaf.size < 32) {
            throw InvalidXmrLicenseException("Embedded leaf license is ${embeddedLeaf.size} bytes, expected 32")
        }
        return embeddedLeaf
    }

    /**
     * Check the license's own AES-CMAC over everything preceding its signature object.
     *
     * @throws XmrSignatureException if the license has no signature, or it does not match
     */
    public suspend fun verifyIntegrity(integrityKey: ByteArray) {
        val signatureObject = find(XmrObjectType.SIGNATURE)
            ?: throw XmrSignatureException("License carries no signature object")

        val reader = ByteReader(signatureObject.body)
        reader.u16("signature type")
        val length = reader.u16("signature length")
        val signature = reader.bytes(length, "signature data")

        val expected = aesCmac(integrityKey, raw.copyOf(signatureObject.offset))
        if (!constantTimeEquals(expected, signature)) {
            throw XmrSignatureException("License integrity signature does not match")
        }
    }

    override fun toString(): String = "XmrLicense(version=$version, ${objects.size} top-level objects)"

    public companion object {
        private val MAGIC = byteArrayOf('X'.code.toByte(), 'M'.code.toByte(), 'R'.code.toByte(), 0)

        /** Bytes of embedded root license ahead of the leaf, in a scalable content key. */
        private const val EMBEDDED_ROOT_SIZE = 144

        private val SUPPORTED_CIPHERS = setOf(
            PlayreadyCipherType.ECC_256,
            PlayreadyCipherType.ECC_256_WITH_KZ,
            PlayreadyCipherType.ECC_256_VIA_SYMMETRIC,
        )

        /** The constant a scalable license XORs into the root key before deriving from it. */
        private val MAGIC_CONSTANT_ZERO = byteArrayOf(
            0x7e, 0xe9.toByte(), 0xed.toByte(), 0x4a, 0xf7.toByte(), 0x73, 0x22, 0x4f,
            0x00, 0xb8.toByte(), 0xea.toByte(), 0x7e, 0xfb.toByte(), 0x02, 0x7c, 0xbb.toByte(),
        )

        /**
         * Parse an XMR license.
         *
         * @throws InvalidXmrLicenseException if the magic or object framing is wrong
         */
        public fun loads(data: ByteArray): XmrLicense {
            val reader = ByteReader(data)

            val magic = reader.bytes(4, "XMR magic")
            if (!magic.contentEquals(MAGIC)) {
                throw InvalidXmrLicenseException("Data does not start with the XMR magic")
            }

            val version = reader.u32("XMR version")
            val rightsId = reader.bytes(16, "rights id")

            val objects = mutableListOf<XmrObject>()
            while (reader.remaining > 0) {
                objects += parseObject(reader)
            }

            return XmrLicense(data, version, rightsId, objects)
        }

        /** Parse a Base64-encoded XMR license, the form a SOAP response carries. */
        public fun loads(base64: String): XmrLicense = loads(
            try {
                Base64.decode(base64.trim())
            } catch (e: Throwable) {
                throw InvalidXmrLicenseException("XMR license is not valid Base64, $e")
            },
        )

        private fun parseObject(reader: ByteReader): XmrObject {
            val offset = reader.position
            val flags = reader.u16("XMR object flags")
            val type = reader.u16("XMR object type")
            val length = reader.u32("XMR object length")

            if (length < XmrObject.HEADER_SIZE) {
                throw InvalidXmrLicenseException("XMR object length $length is smaller than its header")
            }
            val bodySize = reader.countOf(length - XmrObject.HEADER_SIZE, "XMR object")
            val isContainer = flags == XmrObject.CONTAINER_FLAG ||
                flags == XmrObject.CONTAINER_WITH_MUST_UNDERSTAND_FLAG

            if (!isContainer) {
                return XmrObject(
                    flags = flags,
                    type = XmrObjectType.of(type),
                    body = reader.bytes(bodySize, "XMR object body"),
                    children = emptyList(),
                    offset = offset,
                )
            }

            val inner = reader.slice(bodySize, "XMR container body")
            val children = mutableListOf<XmrObject>()
            while (inner.remaining > 0) {
                children += parseObject(inner)
            }
            return XmrObject(
                flags = flags,
                type = XmrObjectType.of(type),
                body = ByteArray(0),
                children = children,
                offset = offset,
            )
        }
    }
}
