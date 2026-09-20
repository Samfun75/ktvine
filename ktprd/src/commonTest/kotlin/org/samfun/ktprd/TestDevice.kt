package org.samfun.ktprd

import org.samfun.ktprd.bcert.BCERT_KEY_TYPE_ECC256
import org.samfun.ktprd.bcert.BCERT_SIGNATURE_TYPE_P256
import org.samfun.ktprd.bcert.BCertFlag
import org.samfun.ktprd.bcert.BCertKeyUsage
import org.samfun.ktprd.bcert.BCertObjectFlag
import org.samfun.ktprd.bcert.BCertObjectType
import org.samfun.ktprd.bcert.BCertType
import org.samfun.ktprd.bcert.Certificate
import org.samfun.ktprd.bcert.CertificateAttribute
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.bcert.Provisioning
import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyDevice
import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.crypto.sha256
import org.samfun.ktprd.utils.ByteWriter
import org.samfun.ktprd.utils.align4
import org.samfun.ktvine.crypto.randomBytes

/**
 * Builds a throwaway PlayReady device with no real provisioning material.
 *
 * The real devices are git-ignored and JVM-only, so anything that has to run on iOS and Linux
 * needs a device it can manufacture. The chain here terminates at a made-up root, which is fine
 * for everything except [CertificateChain.verify] — a CDM never verifies its own chain.
 */
object TestDevice {

    suspend fun create(securityLevel: Int = 3000): PlayreadyDevice {
        val rootKey = EccKey.generate()
        val groupKey = EccKey.generate()
        val signingKey = EccKey.generate()
        val encryptionKey = EccKey.generate()

        val issuer = buildIssuer(securityLevel, groupKey, rootKey)
        val issuerChain = CertificateChain(version = 1, flags = 0, certificates = listOf(issuer))

        val leaf = Provisioning.newLeafCertificate(issuerChain, groupKey, signingKey, encryptionKey)
        return PlayreadyDevice.of(groupKey, encryptionKey, signingKey, issuerChain.prepend(leaf))
    }

    /** A one-certificate chain whose leaf may sign license responses, with its private key. */
    suspend fun responseSigner(): Pair<CertificateChain, EccKey> {
        val signingKey = EccKey.generate()
        val certificate = buildIssuer(
            securityLevel = 3000,
            groupKey = signingKey,
            rootKey = EccKey.generate(),
            certType = BCertType.LICENSE_SIGNER,
            keyUsage = BCertKeyUsage.SIGN_RESPONSE,
        )
        return CertificateChain(version = 1, flags = 0, certificates = listOf(certificate)) to signingKey
    }

    private suspend fun buildIssuer(
        securityLevel: Int,
        groupKey: EccKey,
        rootKey: EccKey,
        certType: BCertType = BCertType.ISSUER,
        keyUsage: BCertKeyUsage = BCertKeyUsage.ISSUER_DEVICE,
    ): Certificate {
        val basicInfo = ByteWriter()
            .bytes(randomBytes(16))
            .u32(securityLevel)
            .u32(BCertFlag.EMPTY)
            .u32(certType.value)
            .bytes(sha256(groupKey.publicBytes))
            .u32(Provisioning.NEVER_EXPIRES)
            .bytes(randomBytes(16))
            .toByteArray()

        val keyInfo = ByteWriter()
            .u32(1)
            .u16(BCERT_KEY_TYPE_ECC256)
            .u16(groupKey.publicBytes.size * 8)
            .u32(BCertFlag.EMPTY)
            .bytes(groupKey.publicBytes)
            .u32(1)
            .u32(keyUsage.value)
            .toByteArray()

        val manufacturer = ByteWriter()
            .u32(0)
            .paddedString("ktprd")
            .paddedString("test device")
            .paddedString("0001")
            .toByteArray()

        val attributes = listOf(
            attribute(BCertObjectType.BASIC, basicInfo),
            attribute(BCertObjectType.KEY, keyInfo),
            attribute(BCertObjectType.MANUFACTURER, manufacturer),
        )

        val certificateLength =
            Certificate.HEADER_SIZE + attributes.sumOf { it.body.size + CertificateAttribute.HEADER_SIZE }
        val totalLength = certificateLength + Certificate.SIGNATURE_ATTRIBUTE_SIZE

        val signedPrefix = Certificate.build(1, attributes, certificateLength, totalLength)
        val signature = Ecdsa.sign(rootKey.scalar, signedPrefix)

        val signatureInfo = ByteWriter()
            .u16(BCERT_SIGNATURE_TYPE_P256)
            .u16(signature.size)
            .bytes(signature)
            .u32(rootKey.publicBytes.size * 8)
            .bytes(rootKey.publicBytes)
            .toByteArray()

        val complete = attributes + attribute(BCertObjectType.SIGNATURE, signatureInfo)
        return Certificate.loads(Certificate.build(1, complete, certificateLength, totalLength))
    }

    private fun attribute(tag: BCertObjectType, body: ByteArray) =
        CertificateAttribute(BCertObjectFlag.MUST_UNDERSTAND, tag, body)

    private fun ByteWriter.paddedString(value: String): ByteWriter {
        val bytes = value.encodeToByteArray()
        u32(bytes.size)
        bytes(bytes)
        repeat(align4(bytes.size) - bytes.size) { u8(0) }
        return this
    }
}
