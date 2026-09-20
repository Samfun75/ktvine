package org.samfun.ktprd.bcert

import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyDevice
import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.crypto.KeyWrap
import org.samfun.ktprd.crypto.sha256
import org.samfun.ktprd.utils.ByteWriter
import org.samfun.ktprd.utils.InvalidCertificateChainException
import org.samfun.ktprd.utils.InvalidPrdException
import org.samfun.ktvine.crypto.randomBytes

/**
 * Turning a group certificate and its private key into a usable device.
 *
 * A `bgroupcert.dat` attests to a group, not to a device: its leaf is an `ISSUER` that is entitled
 * to mint device certificates. Provisioning generates a fresh signing and encryption key pair,
 * issues a `DEVICE` leaf for them signed by the group key, and prepends it to the chain.
 *
 * This is library API rather than a CLI; ktvine ships no command-line tool and neither does ktprd.
 */
public object Provisioning {

    /** The expiry value meaning "never". */
    public const val NEVER_EXPIRES: Long = 0xFFFFFFFFL

    private const val MAX_LICENSE = 10240
    private const val MAX_HEADER = 15360
    private const val MAX_CHAIN_DEPTH = 2

    private val LEAF_FEATURES = listOf(
        BCertFeature.SECURE_CLOCK,
        BCertFeature.SUPPORTS_CRLS,
        BCertFeature.SUPPORTS_PLAYREADY_3_FEATURES,
    )

    /**
     * Issue a `DEVICE` certificate for [signingKey] and [encryptionKey], signed by [groupKey].
     *
     * The manufacturer details are carried over from [parent]'s leaf, because they identify the
     * hardware the group certificate was issued for and are not ours to invent.
     *
     * @throws InvalidCertificateChainException if [parent] cannot issue device certificates
     */
    public suspend fun newLeafCertificate(
        parent: CertificateChain,
        groupKey: EccKey,
        signingKey: EccKey,
        encryptionKey: EccKey,
        certId: ByteArray = randomBytes(16),
        clientId: ByteArray = randomBytes(16),
        expiry: Long = NEVER_EXPIRES,
    ): Certificate {
        val issuer = parent.get(0)
        if (issuer.certType != BCertType.ISSUER) {
            throw InvalidCertificateChainException(
                "The chain's leaf is ${issuer.certType}, so it cannot issue a device certificate",
            )
        }
        if (!issuer.containsPublicKey(groupKey.publicBytes)) {
            throw InvalidCertificateChainException("This group key is not the one the chain's leaf holds")
        }

        val securityLevel = parent.securityLevel
            ?: throw InvalidCertificateChainException("The chain declares no security level")
        val manufacturer = issuer.attribute(BCertObjectType.MANUFACTURER)
            ?: throw InvalidCertificateChainException("The chain's leaf declares no manufacturer")

        return buildLeaf(
            securityLevel = securityLevel,
            certId = certId,
            clientId = clientId,
            expiry = expiry,
            signingKey = signingKey,
            encryptionKey = encryptionKey,
            groupKey = groupKey,
            manufacturer = manufacturer,
        )
    }

    internal suspend fun buildLeaf(
        securityLevel: Int,
        certId: ByteArray,
        clientId: ByteArray,
        expiry: Long,
        signingKey: EccKey,
        encryptionKey: EccKey,
        groupKey: EccKey,
        manufacturer: CertificateAttribute,
    ): Certificate {
        val basicInfo = ByteWriter()
            .bytes(certId)
            .u32(securityLevel)
            .u32(BCertFlag.EMPTY)
            .u32(BCertType.DEVICE.value)
            .bytes(sha256(signingKey.publicBytes))
            .u32(expiry)
            .bytes(clientId)
            .toByteArray()

        val deviceInfo = ByteWriter()
            .u32(MAX_LICENSE)
            .u32(MAX_HEADER)
            .u32(MAX_CHAIN_DEPTH)
            .toByteArray()

        val featureInfo = LEAF_FEATURES
            .fold(ByteWriter().u32(LEAF_FEATURES.size)) { writer, feature -> writer.u32(feature.value) }
            .toByteArray()

        val keyInfo = ByteWriter()
            .u32(2)
            .certificateKey(signingKey.publicBytes, BCertKeyUsage.SIGN)
            .certificateKey(encryptionKey.publicBytes, BCertKeyUsage.ENCRYPT_KEY)
            .toByteArray()

        val attributes = listOf(
            mustUnderstand(BCertObjectType.BASIC, basicInfo),
            mustUnderstand(BCertObjectType.DEVICE, deviceInfo),
            mustUnderstand(BCertObjectType.FEATURE, featureInfo),
            mustUnderstand(BCertObjectType.KEY, keyInfo),
            manufacturer,
        )

        // The header states the length the finished certificate will have, signature included,
        // before that signature exists — so these bytes are byte-identical to the corresponding
        // prefix of the final certificate, which is what verification re-hashes.
        val certificateLength = Certificate.HEADER_SIZE +
            attributes.sumOf { it.body.size + CertificateAttribute.HEADER_SIZE }
        val totalLength = certificateLength + Certificate.SIGNATURE_ATTRIBUTE_SIZE

        val signedPrefix = Certificate.build(1, attributes, certificateLength, totalLength)
        val signature = Ecdsa.sign(groupKey.scalar, signedPrefix)

        val signatureInfo = ByteWriter()
            .u16(BCERT_SIGNATURE_TYPE_P256)
            .u16(signature.size)
            .bytes(signature)
            .u32(groupKey.publicBytes.size * 8)
            .bytes(groupKey.publicBytes)
            .toByteArray()

        val complete = attributes + mustUnderstand(BCertObjectType.SIGNATURE, signatureInfo)
        return Certificate.loads(Certificate.build(1, complete, certificateLength, totalLength))
    }

    /**
     * Provision a device from a group certificate and its private key.
     *
     * @param encryptionKey reuse an existing key, or leave `null` to generate one
     * @param signingKey likewise
     * @throws InvalidCertificateChainException if the chain is already provisioned
     */
    public suspend fun createDevice(
        groupCertificate: CertificateChain,
        groupKey: EccKey,
        encryptionKey: EccKey? = null,
        signingKey: EccKey? = null,
    ): PlayreadyDevice {
        if (groupCertificate.get(0).certType == BCertType.DEVICE) {
            throw InvalidCertificateChainException("This chain is already provisioned")
        }

        val encryption = encryptionKey ?: EccKey.generate()
        val signing = signingKey ?: EccKey.generate()

        val leaf = newLeafCertificate(groupCertificate, groupKey, signing, encryption)
        return PlayreadyDevice.of(groupKey, encryption, signing, groupCertificate.prepend(leaf))
    }

    /**
     * Re-issue a device's leaf certificate with fresh keys.
     *
     * @throws InvalidPrdException if the device has no group key, so cannot sign a new leaf
     */
    public suspend fun reprovision(
        device: PlayreadyDevice,
        encryptionKey: EccKey? = null,
        signingKey: EccKey? = null,
    ): PlayreadyDevice {
        val groupKey = device.groupKey
            ?: throw InvalidPrdException("This device carries no group key, so it cannot be reprovisioned")

        return createDevice(
            groupCertificate = device.groupCertificate.removeLeaf(),
            groupKey = groupKey,
            encryptionKey = encryptionKey ?: EccKey.generate(),
            signingKey = signingKey ?: EccKey.generate(),
        )
    }

    /**
     * Split a device back into the raw files it was built from.
     *
     * @return the `zgpriv.dat` private group key and the un-provisioned `bgroupcert.dat` chain
     * @throws InvalidPrdException if the device has no group key to export
     */
    public fun exportRawKeys(device: PlayreadyDevice): Pair<ByteArray, ByteArray> {
        val groupKey = device.groupKey
            ?: throw InvalidPrdException("This device carries no group key, so there is nothing to export")
        return groupKey.dumps(privateOnly = true) to device.groupCertificate.removeLeaf().dumps()
    }

    /** Unwrap a `zgpriv_protected.dat` into the group key it holds. */
    public suspend fun unwrapProtectedGroupKey(wrapped: ByteArray): EccKey =
        EccKey.loads(KeyWrap.unwrapGroupKey(wrapped))

    private fun mustUnderstand(tag: BCertObjectType, body: ByteArray): CertificateAttribute =
        CertificateAttribute(BCertObjectFlag.MUST_UNDERSTAND, tag, body)

    private fun ByteWriter.certificateKey(publicBytes: ByteArray, usage: BCertKeyUsage): ByteWriter = this
        .u16(BCERT_KEY_TYPE_ECC256)
        .u16(publicBytes.size * 8)
        .u32(BCertFlag.EMPTY)
        .bytes(publicBytes)
        .u32(1)
        .u32(usage.value)
}
