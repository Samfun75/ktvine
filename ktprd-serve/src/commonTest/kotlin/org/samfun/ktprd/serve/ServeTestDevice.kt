package org.samfun.ktprd.serve

import org.samfun.ktprd.bcert.BCertKeyUsage
import org.samfun.ktprd.bcert.BCertType
import org.samfun.ktprd.bcert.Certificate
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyDevice

/**
 * A throwaway device for the serve tests, assembled from raw bytes.
 *
 * `:ktprd`'s own test helpers are not visible here, and neither are its internal builders, so this
 * writes the `bcert` framing directly. That is enough: nothing on the serve path verifies a
 * device's chain — a CDM signs with the device's key, it does not re-check who issued it — so the
 * signature attribute here is a placeholder of the right shape rather than a real signature.
 */
object ServeTestDevice {

    const val SECURITY_LEVEL: Int = 3000

    private var cached: PlayreadyDevice? = null

    fun get(): PlayreadyDevice = cached ?: build().also { cached = it }

    private fun build(): PlayreadyDevice {
        val groupKey = EccKey.generate()
        val signingKey = EccKey.generate()
        val encryptionKey = EccKey.generate()

        val basicInfo = Bytes()
            .bytes(ByteArray(16) { it.toByte() })
            .u32(SECURITY_LEVEL)
            .u32(0)
            .u32(BCertType.DEVICE.value)
            .bytes(ByteArray(32))
            .u32(0xFFFFFFFFL)
            .bytes(ByteArray(16))
            .out()

        val keyInfo = Bytes()
            .u32(2)
            .certificateKey(signingKey.publicBytes, BCertKeyUsage.SIGN.value)
            .certificateKey(encryptionKey.publicBytes, BCertKeyUsage.ENCRYPT_KEY.value)
            .out()

        val signatureInfo = Bytes()
            .u16(1)
            .u16(64)
            .bytes(ByteArray(64))
            .u32(groupKey.publicBytes.size * 8)
            .bytes(groupKey.publicBytes)
            .out()

        val attributes = listOf(1 to basicInfo, 6 to keyInfo)
        val body = attributes.fold(Bytes()) { writer, (tag, attribute) -> writer.attribute(tag, attribute) }.out()
        val signatureAttribute = Bytes().attribute(8, signatureInfo).out()

        val certificateLength = CERT_HEADER_SIZE + body.size
        val totalLength = certificateLength + signatureAttribute.size

        val certificate = Bytes()
            .bytes("CERT".encodeToByteArray())
            .u32(1)
            .u32(totalLength.toLong())
            .u32(certificateLength.toLong())
            .bytes(body)
            .bytes(signatureAttribute)
            .out()

        val chain = Bytes()
            .bytes("CHAI".encodeToByteArray())
            .u32(1)
            .u32((CHAIN_HEADER_SIZE + certificate.size).toLong())
            .u32(0)
            .u32(1)
            .bytes(certificate)
            .out()

        return PlayreadyDevice.of(
            groupKey = groupKey,
            encryptionKey = encryptionKey,
            signingKey = signingKey,
            groupCertificate = CertificateChain.loads(chain).also { check(it.get(0) is Certificate) },
        )
    }

    private const val CERT_HEADER_SIZE = 16
    private const val CHAIN_HEADER_SIZE = 20

    /** A minimal big-endian byte accumulator; ktprd's own is internal to that module. */
    private class Bytes {
        private val buffer = mutableListOf<Byte>()

        fun u8(value: Int) = apply { buffer += value.toByte() }

        fun u16(value: Int) = apply {
            u8(value ushr 8)
            u8(value)
        }

        fun u32(value: Long) = apply {
            u8((value ushr 24).toInt())
            u8((value ushr 16).toInt())
            u8((value ushr 8).toInt())
            u8(value.toInt())
        }

        fun u32(value: Int) = u32(value.toLong() and 0xFFFFFFFFL)

        fun bytes(value: ByteArray) = apply { value.forEach { buffer += it } }

        fun attribute(tag: Int, body: ByteArray) = apply {
            u16(1)
            u16(tag)
            u32((body.size + 8).toLong())
            bytes(body)
        }

        fun certificateKey(publicBytes: ByteArray, usage: Int) = apply {
            u16(1)
            u16(publicBytes.size * 8)
            u32(0)
            bytes(publicBytes)
            u32(1)
            u32(usage)
        }

        fun out(): ByteArray = buffer.toByteArray()
    }
}
