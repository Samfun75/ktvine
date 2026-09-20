package org.samfun.ktprd.bcert

import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.utils.ByteReader
import org.samfun.ktprd.utils.ByteWriter
import org.samfun.ktprd.utils.InvalidCertificateException
import org.samfun.ktprd.utils.align4
import org.samfun.ktprd.utils.decodeNulPadded
import kotlin.io.encoding.Base64

/**
 * One attribute inside a certificate, kept as its raw body.
 *
 * Bodies are parsed on demand rather than eagerly: several are documented but never seen in the
 * wild, and re-encoding a body we only half understand would corrupt the signed bytes.
 */
public class CertificateAttribute internal constructor(
    /** `MUST_UNDERSTAND` and `CONTAINER` bits. */
    public val flags: Int,
    public val tag: BCertObjectType,
    /** The attribute body, without the 8-byte header. */
    public val body: ByteArray,
) {
    internal fun encode(): ByteArray = ByteWriter()
        .u16(flags)
        .u16(tag.value)
        .u32(body.size + HEADER_SIZE)
        .bytes(body)
        .toByteArray()

    override fun toString(): String = "CertificateAttribute(tag=$tag, ${body.size} bytes)"

    internal companion object {
        const val HEADER_SIZE: Int = 8
    }
}

/** A key listed in a certificate's key attribute, with the usages it is authorised for. */
public class CertificateKey internal constructor(
    public val type: Int,
    /** The public point, 64 bytes of `X‖Y`. */
    public val key: ByteArray,
    public val usages: List<BCertKeyUsage>,
)

/** The manufacturer, model name and model number a certificate declares. */
public class ManufacturerInfo internal constructor(
    public val manufacturer: String,
    public val modelName: String,
    public val modelNumber: String,
) {
    override fun toString(): String = listOf(manufacturer, modelName, modelNumber)
        .filter { it.isNotEmpty() }
        .joinToString(" ")
}

/**
 * A single PlayReady `bcert` certificate.
 *
 * The bytes it was parsed from are kept verbatim: a certificate's signature covers its own
 * [certificateLength]-byte prefix, and re-encoding attributes we do not fully model would change
 * those bytes and break verification.
 */
public class Certificate internal constructor(
    /** Exactly the bytes this certificate occupied. */
    public val raw: ByteArray,
    public val version: Long,
    public val totalLength: Int,
    /** Length of the prefix the signature attribute covers. */
    public val certificateLength: Int,
    public val attributes: List<CertificateAttribute>,
) {
    public fun attribute(tag: BCertObjectType): CertificateAttribute? = attributes.firstOrNull { it.tag == tag }

    /** `150`, `2000` or `3000` on a real device. */
    public val securityLevel: Int? get() = basicInfo()?.securityLevel

    public val certType: BCertType? get() = basicInfo()?.certType

    /** Seconds since the Unix epoch; `0xFFFFFFFF` means "never". */
    public val expirationDate: Long? get() = basicInfo()?.expirationDate

    public val clientId: ByteArray? get() = basicInfo()?.clientId

    internal val hasExtendedData: Boolean get() = ((basicInfo()?.flags ?: 0) and BCertFlag.EXT_DATA_PRESENT) != 0

    /** A human-readable device name, or `null` when the certificate declares no manufacturer. */
    public val name: String? get() = manufacturerInfo()?.toString()

    /** The public key of whoever signed this certificate. */
    public val issuerKey: ByteArray? get() = signatureInfo()?.signatureKey

    public fun keyByUsage(usage: BCertKeyUsage): ByteArray? = keys().firstOrNull { usage in it.usages }?.key

    public fun containsPublicKey(publicBytes: ByteArray): Boolean = keys().any { it.key.contentEquals(publicBytes) }

    public fun dumps(): ByteArray = raw.copyOf()

    override fun toString(): String = "Certificate(type=$certType, securityLevel=$securityLevel, name=$name)"

    /**
     * Verify this certificate's own signature, and its extended-data signature when present.
     *
     * This says the certificate was signed by whoever holds [issuerKey]; it says nothing about
     * whether that issuer is trusted. [CertificateChain.verify] is what establishes that.
     *
     * @throws InvalidCertificateException if a required attribute is missing or a signature fails
     */
    public suspend fun verifySignature() {
        val signature = signatureInfo()
            ?: throw InvalidCertificateException("Certificate has no signature attribute")

        if (certificateLength > raw.size) {
            throw InvalidCertificateException(
                "Certificate claims a signed prefix of $certificateLength bytes but is only ${raw.size}",
            )
        }

        val signedPrefix = raw.copyOf(certificateLength)
        if (!Ecdsa.verify(signature.signatureKey, signedPrefix, signature.signature)) {
            throw InvalidCertificateException("Certificate signature is not authentic")
        }

        if (hasExtendedData) verifyExtendedDataSignature()
    }

    private suspend fun verifyExtendedDataSignature() {
        val signKey = attribute(BCertObjectType.EXT_DATA_SIGN_KEY)
            ?: throw InvalidCertificateException("Certificate declares extended data but has no signing key for it")
        val container = attribute(BCertObjectType.EXT_DATA_CONTAINER)
            ?: throw InvalidCertificateException("Certificate declares extended data but carries no container")

        val keyReader = ByteReader(signKey.body)
        keyReader.u16("extended data key type")
        val keyBits = keyReader.u16("extended data key length")
        keyReader.u32("extended data key flags")
        val publicKey = keyReader.bytes(keyBits / 8, "extended data signing key")

        // The container holds a record then a signature, each with its own attribute header; the
        // signature covers the record including that header.
        val reader = ByteReader(container.body)
        reader.u16("extended data record flags")
        reader.u16("extended data record tag")
        val recordLength = reader.countOf(reader.u32("extended data record length"), "extended data record")
        if (recordLength < CertificateAttribute.HEADER_SIZE) {
            throw InvalidCertificateException("Extended data record length $recordLength is too small")
        }
        val signedRecord = container.body.copyOf(recordLength)

        reader.skip(recordLength - CertificateAttribute.HEADER_SIZE, "extended data record body")
        reader.u16("extended data signature flags")
        reader.u16("extended data signature tag")
        reader.u32("extended data signature length")
        reader.u16("extended data signature type")
        val signatureSize = reader.u16("extended data signature size")
        val signature = reader.bytes(signatureSize, "extended data signature")

        if (!Ecdsa.verify(publicKey, signedRecord, signature)) {
            throw InvalidCertificateException("Extended data signature is not authentic")
        }
    }

    internal class BasicInfo(
        val certId: ByteArray,
        val securityLevel: Int,
        val flags: Int,
        val certType: BCertType,
        val publicKeyDigest: ByteArray,
        val expirationDate: Long,
        val clientId: ByteArray,
    )

    internal class SignatureInfo(
        val signatureType: Int,
        val signature: ByteArray,
        val signatureKey: ByteArray,
    )

    internal fun basicInfo(): BasicInfo? {
        val body = attribute(BCertObjectType.BASIC)?.body ?: return null
        val reader = ByteReader(body)
        return BasicInfo(
            certId = reader.bytes(16, "certificate id"),
            securityLevel = reader.u32("security level").toInt(),
            flags = reader.u32("basic info flags").toInt(),
            certType = BCertType.of(reader.u32("certificate type").toInt()),
            publicKeyDigest = reader.bytes(32, "public key digest"),
            expirationDate = reader.u32("expiration date"),
            clientId = reader.bytes(16, "client id"),
        )
    }

    internal fun signatureInfo(): SignatureInfo? {
        val body = attribute(BCertObjectType.SIGNATURE)?.body ?: return null
        val reader = ByteReader(body)
        val signatureType = reader.u16("signature type")
        val signatureSize = reader.u16("signature size")
        val signature = reader.bytes(signatureSize, "signature")
        val keyBits = reader.countOf(reader.u32("signature key size") / 8, "signature key")
        return SignatureInfo(signatureType, signature, reader.bytes(keyBits, "signature key"))
    }

    /** Every key the certificate lists, in declaration order. */
    public fun keys(): List<CertificateKey> {
        val body = attribute(BCertObjectType.KEY)?.body ?: return emptyList()
        val reader = ByteReader(body)
        val count = reader.countOf(reader.u32("key count"), "key list")
        return List(count) {
            val type = reader.u16("key type")
            val bits = reader.u16("key length")
            reader.u32("key flags")
            val key = reader.bytes(bits / 8, "certificate key")
            val usageCount = reader.countOf(reader.u32("key usage count"), "key usages")
            CertificateKey(type, key, List(usageCount) { BCertKeyUsage.of(reader.u32("key usage").toInt()) })
        }
    }

    /** Every feature the certificate declares. */
    public fun features(): List<BCertFeature> {
        val body = attribute(BCertObjectType.FEATURE)?.body ?: return emptyList()
        val reader = ByteReader(body)
        val count = reader.countOf(reader.u32("feature count"), "feature list")
        return List(count) { BCertFeature.of(reader.u32("feature").toInt()) }
    }

    public fun manufacturerInfo(): ManufacturerInfo? {
        val body = attribute(BCertObjectType.MANUFACTURER)?.body ?: return null
        val reader = ByteReader(body)
        reader.u32("manufacturer flags")
        return ManufacturerInfo(
            manufacturer = reader.paddedString("manufacturer name"),
            modelName = reader.paddedString("model name"),
            modelNumber = reader.paddedString("model number"),
        )
    }

    private fun ByteReader.paddedString(what: String): String {
        val length = countOf(u32("$what length"), what)
        return bytes(align4(length), what).decodeNulPadded()
    }

    public companion object {
        internal val MAGIC = byteArrayOf('C'.code.toByte(), 'E'.code.toByte(), 'R'.code.toByte(), 'T'.code.toByte())

        internal const val HEADER_SIZE: Int = 16

        /** Bytes a P-256 signature attribute occupies: header, type, size, 64-byte r-s, key size, 64-byte key. */
        internal const val SIGNATURE_ATTRIBUTE_SIZE: Int = 144

        /**
         * Parse one `CERT` certificate.
         *
         * @throws InvalidCertificateException if the magic, lengths or attribute framing are wrong
         */
        public fun loads(data: ByteArray): Certificate = parse(ByteReader(data))

        /** Parse a Base64-encoded certificate. */
        public fun loads(base64: String): Certificate = loads(decodeBase64(base64, "Certificate"))

        internal fun decodeBase64(value: String, what: String): ByteArray = try {
            Base64.decode(value.trim())
        } catch (e: Throwable) {
            throw InvalidCertificateException("$what is not valid Base64, $e")
        }

        internal fun parse(reader: ByteReader): Certificate {
            val start = reader.position
            val magic = reader.bytes(4, "certificate magic")
            if (!magic.contentEquals(MAGIC)) {
                throw InvalidCertificateException("Certificate does not start with CERT")
            }

            val version = reader.u32("certificate version")
            val totalLength = reader.countOf(reader.u32("certificate total length") - HEADER_SIZE, "certificate")
            val certificateLength = reader.u32("certificate signed length").toInt()

            if (certificateLength < HEADER_SIZE || certificateLength > totalLength + HEADER_SIZE) {
                throw InvalidCertificateException(
                    "Certificate signed length $certificateLength is outside its " +
                        "${totalLength + HEADER_SIZE}-byte body",
                )
            }

            val attributes = mutableListOf<CertificateAttribute>()
            val body = reader.slice(totalLength, "certificate attributes")
            while (body.remaining > 0) {
                attributes += parseAttribute(body)
            }

            return Certificate(
                raw = reader.sliceSince(start),
                version = version,
                totalLength = totalLength + HEADER_SIZE,
                certificateLength = certificateLength,
                attributes = attributes,
            )
        }

        private fun parseAttribute(reader: ByteReader): CertificateAttribute {
            val flags = reader.u16("attribute flags")
            val tag = reader.u16("attribute tag")
            val length = reader.u32("attribute length")
            if (length < CertificateAttribute.HEADER_SIZE) {
                throw InvalidCertificateException("Certificate attribute length $length is too small")
            }
            val bodySize = reader.countOf(length - CertificateAttribute.HEADER_SIZE, "certificate attribute")
            return CertificateAttribute(flags, BCertObjectType.of(tag), reader.bytes(bodySize, "attribute body"))
        }

        /**
         * Encode a certificate with explicit length fields.
         *
         * The lengths are passed in rather than derived because the signed prefix must describe the
         * finished certificate — including the size of a signature that does not exist yet — so the
         * bytes signed are byte-identical to the corresponding prefix of the final certificate.
         */
        internal fun build(
            version: Long,
            attributes: List<CertificateAttribute>,
            certificateLength: Int,
            totalLength: Int,
        ): ByteArray {
            val body = attributes.fold(ByteWriter()) { writer, attribute -> writer.bytes(attribute.encode()) }
                .toByteArray()

            return ByteWriter()
                .bytes(MAGIC)
                .u32(version)
                .u32(totalLength.toLong())
                .u32(certificateLength.toLong())
                .bytes(body)
                .toByteArray()
        }
    }
}
