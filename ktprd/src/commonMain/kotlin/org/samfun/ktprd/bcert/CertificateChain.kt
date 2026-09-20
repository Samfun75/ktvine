package org.samfun.ktprd.bcert

import org.samfun.ktprd.utils.ByteReader
import org.samfun.ktprd.utils.ByteWriter
import org.samfun.ktprd.utils.InvalidCertificateChainException
import org.samfun.ktprd.utils.InvalidCertificateException
import kotlin.io.encoding.Base64

/**
 * A PlayReady `bcert` certificate chain, leaf first.
 *
 * This is the content of a `bgroupcert.dat`, of the group-certificate slot inside a `.prd`, and of
 * the `SigningCertificateChain` a license server returns.
 *
 * Chains are immutable: [prepend] and [removeLeaf] return new chains rather than editing in place,
 * so a chain that has already been verified cannot be changed out from under that result.
 */
public class CertificateChain internal constructor(
    public val version: Long,
    public val flags: Long,
    public val certificates: List<Certificate>,
) {
    public val count: Int get() = certificates.size

    /**
     * @throws InvalidCertificateChainException if the chain is empty or [index] is past its end
     */
    public fun get(index: Int): Certificate {
        if (index !in certificates.indices) {
            throw InvalidCertificateChainException("No certificate at index $index; the chain holds $count")
        }
        return certificates[index]
    }

    /** The leaf's security level: `150`, `2000` or `3000` on a real device. */
    public val securityLevel: Int? get() = certificates.firstOrNull()?.securityLevel

    /** The leaf's device name. */
    public val name: String? get() = certificates.firstOrNull()?.name

    public fun prepend(certificate: Certificate): CertificateChain =
        CertificateChain(version, flags, listOf(certificate) + certificates)

    /**
     * The chain with its leaf removed — how a provisioned device is turned back into a group
     * certificate.
     *
     * @throws InvalidCertificateChainException if the chain is empty
     */
    public fun removeLeaf(): CertificateChain {
        if (certificates.isEmpty()) throw InvalidCertificateChainException("The chain holds no certificates")
        return CertificateChain(version, flags, certificates.drop(1))
    }

    public fun dumps(): ByteArray {
        val body = certificates.fold(ByteWriter()) { writer, cert -> writer.bytes(cert.dumps()) }.toByteArray()
        return ByteWriter()
            .bytes(MAGIC)
            .u32(version)
            .u32((HEADER_SIZE + body.size).toLong())
            .u32(flags)
            .u32(certificates.size.toLong())
            .bytes(body)
            .toByteArray()
    }

    public fun dumpsBase64(): String = Base64.encode(dumps())

    override fun toString(): String = "CertificateChain($count certificates, leaf=${certificates.firstOrNull()})"

    /**
     * Verify the chain end to end.
     *
     * Each certificate must be signed by the next one out, each issuer must actually be an
     * [BCertType.ISSUER] that lists the key it signed with, and the outermost certificate must be
     * signed by Microsoft's PlayReady root. Without that last pin a chain would only have to be
     * internally consistent, which anyone can forge.
     *
     * @param checkExpiry also reject a certificate whose expiry has passed, given [nowSeconds]
     * @param expectedLeafType reject a chain whose leaf is not of this type
     * @throws InvalidCertificateChainException if any of that fails
     */
    public suspend fun verify(
        checkExpiry: Boolean = false,
        expectedLeafType: BCertType? = null,
        nowSeconds: Long = 0,
    ) {
        if (count !in 1..MAX_DEPTH) {
            throw InvalidCertificateChainException("A chain must hold 1 to $MAX_DEPTH certificates, this holds $count")
        }

        expectedLeafType?.let {
            if (get(0).certType != it) {
                throw InvalidCertificateChainException("Leaf certificate is ${get(0).certType}, expected $it")
            }
        }

        for (index in certificates.indices) {
            val certificate = get(index)

            try {
                certificate.verifySignature()
            } catch (e: InvalidCertificateException) {
                throw InvalidCertificateChainException("Certificate $index did not verify: ${e.message}")
            }

            if (checkExpiry) {
                val expiry = certificate.expirationDate
                    ?: throw InvalidCertificateChainException("Certificate $index has no expiration date")
                if (expiry != NEVER_EXPIRES && nowSeconds >= expiry) {
                    throw InvalidCertificateChainException("Certificate $index expired at $expiry")
                }
            }

            if (index > 0) verifyIssues(child = get(index - 1), issuer = certificate, childIndex = index - 1)

            if (index == count - 1) {
                val rootIssuer = certificate.issuerKey
                if (rootIssuer == null || !rootIssuer.contentEquals(MICROSOFT_ROOT_ISSUER_KEY)) {
                    throw InvalidCertificateChainException("The chain does not terminate at the PlayReady root issuer")
                }
            }
        }
    }

    private fun verifyIssues(child: Certificate, issuer: Certificate, childIndex: Int) {
        if (issuer.certType != BCertType.ISSUER) {
            throw InvalidCertificateChainException(
                "Certificate ${childIndex + 1} is ${issuer.certType}, so it cannot issue certificate $childIndex",
            )
        }

        val issuerKey = child.issuerKey
            ?: throw InvalidCertificateChainException("Certificate $childIndex names no issuer key")

        if (!issuer.containsPublicKey(issuerKey)) {
            throw InvalidCertificateChainException(
                "Certificate $childIndex was signed by a key certificate ${childIndex + 1} does not hold",
            )
        }
    }

    public companion object {
        internal val MAGIC = byteArrayOf('C'.code.toByte(), 'H'.code.toByte(), 'A'.code.toByte(), 'I'.code.toByte())

        internal const val HEADER_SIZE: Int = 20

        /** PlayReady's own limit on how deep a license chain may be. */
        public const val MAX_DEPTH: Int = 6

        /** The expiry value that means "never". */
        public const val NEVER_EXPIRES: Long = 0xFFFFFFFFL

        /** Microsoft's PlayReady root issuer public key; every genuine chain terminates here. */
        public val MICROSOFT_ROOT_ISSUER_KEY: ByteArray = byteArrayOf(
            0x86.toByte(), 0x4D, 0x61, 0xCF.toByte(), 0xF2.toByte(), 0x25, 0x6E, 0x42,
            0x2C, 0x56, 0x8B.toByte(), 0x3C, 0x28, 0x00, 0x1C, 0xFB.toByte(),
            0x3E, 0x15, 0x27, 0x65, 0x85.toByte(), 0x84.toByte(), 0xBA.toByte(), 0x05,
            0x21, 0xB7.toByte(), 0x9B.toByte(), 0x18, 0x28, 0xD9.toByte(), 0x36, 0xDE.toByte(),
            0x1D, 0x82.toByte(), 0x6A, 0x8F.toByte(), 0xC3.toByte(), 0xE6.toByte(), 0xE7.toByte(), 0xFA.toByte(),
            0x7A, 0x90.toByte(), 0xD5.toByte(), 0xCA.toByte(), 0x29, 0x46, 0xF1.toByte(), 0xF6.toByte(),
            0x4A, 0x2E, 0xFB.toByte(), 0x9F.toByte(), 0x5D, 0xCF.toByte(), 0xFE.toByte(), 0x7E,
            0x43, 0x4E, 0xB4.toByte(), 0x42, 0x93.toByte(), 0xFA.toByte(), 0xC5.toByte(), 0xAB.toByte(),
        )

        /**
         * Parse a `CHAI` chain.
         *
         * @throws InvalidCertificateChainException if the magic or the certificate count are wrong
         */
        public fun loads(data: ByteArray): CertificateChain {
            val reader = ByteReader(data)

            val magic = reader.bytes(4, "certificate chain magic")
            if (!magic.contentEquals(MAGIC)) {
                throw InvalidCertificateChainException("Certificate chain does not start with CHAI")
            }

            val version = reader.u32("chain version")
            reader.u32("chain total length")
            val flags = reader.u32("chain flags")
            val declared = reader.u32("certificate count")
            if (declared < 0 || declared > MAX_DEPTH) {
                throw InvalidCertificateChainException("Certificate chain declares $declared certificates")
            }

            val certificates = List(declared.toInt()) { index ->
                try {
                    Certificate.parse(reader)
                } catch (e: InvalidCertificateException) {
                    throw InvalidCertificateChainException("Certificate $index in the chain is invalid: ${e.message}")
                }
            }

            return CertificateChain(version, flags, certificates)
        }

        /** Parse a Base64-encoded chain. */
        public fun loads(base64: String): CertificateChain = loads(
            try {
                Base64.decode(base64.trim())
            } catch (e: Throwable) {
                throw InvalidCertificateChainException("Certificate chain is not valid Base64, $e")
            },
        )
    }
}
