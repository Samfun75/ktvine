package org.samfun.ktprd

import org.samfun.ktprd.bcert.BCertKeyUsage
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.core.PlayreadyCipherType
import org.samfun.ktprd.core.PlayreadyKeyType
import org.samfun.ktprd.crypto.EcPoint
import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.crypto.ElGamal
import org.samfun.ktprd.crypto.P256
import org.samfun.ktprd.crypto.sha256
import org.samfun.ktprd.utils.ByteWriter
import org.samfun.ktprd.xmr.XmrObjectType
import org.samfun.ktvine.crypto.aesCbcDecrypt
import org.samfun.ktvine.crypto.aesCmac
import org.samfun.ktvine.crypto.pkcs7Unpad
import org.samfun.ktvine.utils.toLittleEndianByteArray
import kotlin.io.encoding.Base64
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Plays the license server for an offline exchange.
 *
 * It does what a real server does: ElGamal-decrypt the session point with its own WMRM private
 * key, derive the AES pair from it, read the client's certificate chain out of the encrypted
 * blob, check the challenge's own digest and signature, and issue an XMR license encrypted to the
 * device's encryption key.
 *
 * The signature check is the point of the whole exercise. It re-hashes the `<LA>` and
 * `<SignedInfo>` spans out of the transmitted document, so it fails unless the bytes the challenge
 * builder hashed are exactly the bytes it sent.
 */
class TestLicenseServer {

    private val privateScalar = ElGamal.randomScalar()

    /** The server key a CDM under test must be pointed at. */
    internal val publicPoint: EcPoint = P256.publicPoint(privateScalar)

    /** The content key this server will issue. Set after [issueLicense] runs. */
    var issuedKey: ByteArray = ByteArray(0)
        private set

    /**
     * Handle a challenge and return a license response.
     *
     * @param kid the key id to issue a key for
     * @param sign whether to sign the response, exercising the client's own verification
     * @param revocationInfo a `RevInfo` document to send back alongside the license
     */
    suspend fun issueLicense(
        challenge: String,
        kid: Uuid,
        sign: Boolean = false,
        revocationInfo: String? = null,
    ): String {
        val cipherValues = CIPHER_VALUE.findAll(challenge).map { it.groupValues[1] }.toList()
        assertEquals(2, cipherValues.size, "a challenge carries the session point then the client data")

        val sessionPointX = ElGamal.decrypt(Base64.decode(cipherValues[0]), privateScalar)
        val iv = sessionPointX.copyOfRange(0, 16)
        val key = sessionPointX.copyOfRange(16, 32)

        val clientData = Base64.decode(cipherValues[1])
        assertTrue(iv.contentEquals(clientData.copyOf(16)), "the client data must be prefixed with its own IV")

        val plaintext = pkcs7Unpad(aesCbcDecrypt(key, iv, clientData.copyOfRange(16, clientData.size)))
            .decodeToString()

        verifyChallengeSignature(challenge)

        val chain = CertificateChain.loads(
            CERTIFICATE_CHAIN.find(plaintext)?.groupValues?.get(1)?.trim()
                ?: error("the client data carried no certificate chain"),
        )
        val encryptionKey = chain.get(0).keyByUsage(BCertKeyUsage.ENCRYPT_KEY)
            ?: error("the client certificate declares no encryption key")

        return respond(buildXmrLicense(encryptionKey, kid), sign, revocationInfo)
    }

    /**
     * Re-derive the challenge's own digest and signature from the document as sent.
     *
     * A serializer round trip anywhere in the builder would show up here as a mismatch.
     */
    private suspend fun verifyChallengeSignature(challenge: String) {
        val la = span(challenge, "LA") ?: error("the challenge carries no LA element")
        val signedInfo = span(challenge, "SignedInfo") ?: error("the challenge carries no SignedInfo element")

        val declaredDigest = DIGEST_VALUE.find(challenge)?.groupValues?.get(1)
            ?: error("the challenge declares no digest")
        assertEquals(
            Base64.encode(sha256(la.encodeToByteArray())),
            declaredDigest,
            "the declared digest does not cover the LA element as transmitted",
        )

        val signature = Base64.decode(
            SIGNATURE_VALUE.find(challenge)?.groupValues?.get(1) ?: error("the challenge carries no signature"),
        )
        val publicKey = Base64.decode(
            PUBLIC_KEY.find(challenge)?.groupValues?.get(1) ?: error("the challenge carries no public key"),
        )

        assertTrue(
            Ecdsa.verify(publicKey, signedInfo.encodeToByteArray(), signature),
            "the signature does not cover the SignedInfo element as transmitted",
        )
    }

    private suspend fun buildXmrLicense(deviceKey: ByteArray, kid: Uuid): ByteArray {
        // The key material a server issues is the X coordinate of a point, because that is what
        // ElGamal can carry; the low half of it becomes the content key.
        val point = P256.publicPoint(ElGamal.randomScalar())
        val material = P256.toFixed32(point.x)
        issuedKey = material.copyOfRange(16, 32)

        val encrypted = ElGamal.encrypt(point, P256.decodePoint(deviceKey))

        val eccKeyObject = xmrObject(
            XmrObjectType.ECC_DEVICE_KEY,
            ByteWriter().u16(1).u16(deviceKey.size).bytes(deviceKey).toByteArray(),
        )
        val contentKeyObject = xmrObject(
            XmrObjectType.CONTENT_KEY,
            ByteWriter()
                .bytes(kid.toLittleEndianByteArray())
                .u16(PlayreadyKeyType.AES_128_CTR.value)
                .u16(PlayreadyCipherType.ECC_256.value)
                .u16(encrypted.size)
                .bytes(encrypted)
                .toByteArray(),
        )

        val prefix = ByteWriter()
            .bytes(byteArrayOf('X'.code.toByte(), 'M'.code.toByte(), 'R'.code.toByte(), 0))
            .u32(1)
            .bytes(ByteArray(16))
            .bytes(
                container(
                    XmrObjectType.OUTER_CONTAINER,
                    container(XmrObjectType.KEY_MATERIAL_CONTAINER, eccKeyObject, contentKeyObject),
                ),
            )
            .toByteArray()

        val signature = aesCmac(material.copyOfRange(0, 16), prefix)
        return prefix + xmrObject(
            XmrObjectType.SIGNATURE,
            ByteWriter().u16(1).u16(signature.size).bytes(signature).toByteArray(),
        )
    }

    private suspend fun respond(xmrLicense: ByteArray, sign: Boolean, revocationInfo: String?): String {
        val signer = if (sign) TestDevice.responseSigner() else null

        val licenseResponse = buildString {
            append("<LicenseResponse>")
            append("<Version>1</Version>")
            append("<Licenses><License>").append(Base64.encode(xmrLicense)).append("</License></Licenses>")
            revocationInfo?.let { append(it) }
            append("<ResponseID>1</ResponseID>")
            signer?.let {
                append("<SigningCertificateChain>").append(it.first.dumpsBase64()).append("</SigningCertificateChain>")
            }
            append("</LicenseResponse>")
        }

        val signatureBlock = signer?.let { buildSignature(licenseResponse, it.second) }.orEmpty()

        return buildString {
            append("<?xml version=\"1.0\" encoding=\"utf-8\"?>")
            append("<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body>")
            append("<AcquireLicenseResponse xmlns=\"http://schemas.microsoft.com/DRM/2007/03/protocols\">")
            append("<AcquireLicenseResult><Response>")
            append(licenseResponse)
            append(signatureBlock)
            append("</Response></AcquireLicenseResult></AcquireLicenseResponse>")
            append("</soap:Body></soap:Envelope>")
        }
    }

    /** A response signature over the `LicenseResponse` element exactly as it will be sent. */
    private suspend fun buildSignature(licenseResponse: String, signingKey: org.samfun.ktprd.core.EccKey): String {
        val signedInfo = buildString {
            append("<SignedInfo><Reference><DigestValue>")
            append(Base64.encode(sha256(licenseResponse.encodeToByteArray())))
            append("</DigestValue></Reference></SignedInfo>")
        }
        val signature = Ecdsa.sign(signingKey.scalar, signedInfo.encodeToByteArray())

        return buildString {
            append("<Signature>")
            append(signedInfo)
            append("<SignatureValue>").append(Base64.encode(signature)).append("</SignatureValue>")
            append("</Signature>")
        }
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

    private companion object {
        val CIPHER_VALUE = Regex("<CipherValue>([^<]*)</CipherValue>")
        val CERTIFICATE_CHAIN = Regex("<CertificateChain>([^<]*)</CertificateChain>")
        val DIGEST_VALUE = Regex("<DigestValue>([^<]*)</DigestValue>")
        val SIGNATURE_VALUE = Regex("<SignatureValue>([^<]*)</SignatureValue>")
        val PUBLIC_KEY = Regex("<PublicKey>([^<]*)</PublicKey>")

        /** The `<name>…</name>` span of [name], tags included. */
        fun span(document: String, name: String): String? {
            val start = document.indexOf("<$name ").takeIf { it >= 0 }
                ?: document.indexOf("<$name>").takeIf { it >= 0 }
                ?: return null
            val end = document.indexOf("</$name>", start).takeIf { it >= 0 } ?: return null
            return document.substring(start, end + name.length + 3)
        }
    }
}
