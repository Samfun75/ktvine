@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd.soap

import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.crypto.EcPoint
import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.crypto.ElGamal
import org.samfun.ktprd.crypto.P256
import org.samfun.ktprd.crypto.sha256
import org.samfun.ktvine.crypto.aesCbcEncryptNoPadding
import org.samfun.ktvine.crypto.pkcs7Pad
import org.samfun.ktvine.utils.toLittleEndianByteArray
import kotlin.io.encoding.Base64
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** A revocation list the client claims to already hold, and at which version. */
public class RevocationListVersion(public val listId: Uuid, public val version: Long)

/**
 * Builds the SOAP `AcquireLicense` challenge a PlayReady server expects.
 *
 * **The document is assembled as text, not through a DOM, and that is deliberate.** The challenge
 * carries a SHA-256 digest of its own `<LA>` element and an ECDSA signature over its own
 * `<SignedInfo>` element, both covering literal bytes. Building the string means the bytes hashed
 * are exactly the bytes sent; going through a serializer would mean trusting that re-serializing
 * reproduces them, which is where the reference implementation has to un-escape its own output to
 * undo the escaping it just applied to the embedded `WRMHEADER`.
 *
 * Every element is written in long form (`<X></X>`), never self-closed, because that is what the
 * protocol's own serialization produces and the digest is taken over it.
 */
internal object ChallengeBuilder {

    private const val PROTOCOLS_NS = "http://schemas.microsoft.com/DRM/2007/03/protocols"
    private const val MESSAGES_NS = "http://schemas.microsoft.com/DRM/2007/03/protocols/messages"
    private const val XMLENC_NS = "http://www.w3.org/2001/04/xmlenc#"
    private const val XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
    private const val SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/"

    /**
     * @param wrmHeader the header document, embedded verbatim
     * @param xmlKey the session's ephemeral key, whose point is encrypted to [wmrmPublicPoint]
     * @param nonce 16 random bytes, taken as a parameter so a test can pin the whole document
     * @param clientTimeSeconds seconds since the Unix epoch, likewise
     */
    suspend fun build(
        wrmHeader: String,
        protocolVersion: Int,
        certificateChain: CertificateChain,
        signingKey: EccKey,
        xmlKey: XmlKey,
        wmrmPublicPoint: EcPoint,
        clientVersion: String,
        revocationLists: List<RevocationListVersion>?,
        nonce: ByteArray,
        clientTimeSeconds: Long,
    ): String {
        val licenseAcquisition = buildLicenseAcquisition(
            wrmHeader = wrmHeader,
            protocolVersion = protocolVersion,
            clientVersion = clientVersion,
            revocationLists = revocationLists,
            nonce = nonce,
            clientTimeSeconds = clientTimeSeconds,
            wmrmData = ElGamal.encrypt(xmlKey.point, wmrmPublicPoint),
            clientData = encryptClientData(certificateChain, xmlKey),
        )

        val digest = sha256(licenseAcquisition.encodeToByteArray())
        val signedInfo = buildSignedInfo(digest)
        val signature = Ecdsa.sign(signingKey.scalar, signedInfo.encodeToByteArray())

        val challenge = buildString {
            append("<AcquireLicense xmlns=\"").append(PROTOCOLS_NS).append("\">")
            append("<challenge>")
            append("<Challenge xmlns=\"").append(MESSAGES_NS).append("\">")
            append(licenseAcquisition)
            append("<Signature xmlns=\"").append(XMLDSIG_NS).append("\">")
            append(signedInfo)
            append("<SignatureValue>").append(Base64.encode(signature)).append("</SignatureValue>")
            append("<KeyInfo xmlns=\"").append(XMLDSIG_NS).append("\"><KeyValue><ECCKeyValue>")
            append("<PublicKey>").append(Base64.encode(signingKey.publicBytes)).append("</PublicKey>")
            append("</ECCKeyValue></KeyValue></KeyInfo>")
            append("</Signature>")
            append("</Challenge>")
            append("</challenge>")
            append("</AcquireLicense>")
        }

        return SoapMessage.wrap(challenge)
    }

    private fun buildLicenseAcquisition(
        wrmHeader: String,
        protocolVersion: Int,
        clientVersion: String,
        revocationLists: List<RevocationListVersion>?,
        nonce: ByteArray,
        clientTimeSeconds: Long,
        wmrmData: ByteArray,
        clientData: ByteArray,
    ): String = buildString {
        append("<LA xmlns=\"").append(PROTOCOLS_NS).append("\" Id=\"SignedData\" xml:space=\"preserve\">")
        append("<Version>").append(protocolVersion).append("</Version>")
        // Embedded raw: the digest covers these bytes, and escaping then un-escaping them would
        // only be a way to arrive back here with more chances to differ.
        append("<ContentHeader>").append(wrmHeader).append("</ContentHeader>")
        append("<CLIENTINFO><CLIENTVERSION>").append(escape(clientVersion)).append("</CLIENTVERSION></CLIENTINFO>")

        if (revocationLists != null) {
            append("<RevocationLists>")
            revocationLists.forEach { entry ->
                append("<RevListInfo>")
                append("<ListID>").append(Base64.encode(entry.listId.toLittleEndianByteArray())).append("</ListID>")
                append("<Version>").append(entry.version).append("</Version>")
                append("</RevListInfo>")
            }
            append("</RevocationLists>")
        }

        append("<LicenseNonce>").append(Base64.encode(nonce)).append("</LicenseNonce>")
        append("<ClientTime>").append(clientTimeSeconds).append("</ClientTime>")

        append("<EncryptedData xmlns=\"").append(XMLENC_NS)
        append("\" Type=\"").append(XMLENC_NS).append("Element\">")
        append("<EncryptionMethod Algorithm=\"").append(XMLENC_NS).append("aes128-cbc\"></EncryptionMethod>")
        append("<KeyInfo xmlns=\"").append(XMLDSIG_NS).append("\">")
        append("<EncryptedKey xmlns=\"").append(XMLENC_NS).append("\">")
        append("<EncryptionMethod Algorithm=\"").append(PROTOCOLS_NS).append("#ecc256\"></EncryptionMethod>")
        append("<KeyInfo xmlns=\"").append(XMLDSIG_NS).append("\"><KeyName>WMRMServer</KeyName></KeyInfo>")
        append("<CipherData><CipherValue>").append(Base64.encode(wmrmData)).append("</CipherValue></CipherData>")
        append("</EncryptedKey>")
        append("</KeyInfo>")
        append("<CipherData><CipherValue>").append(Base64.encode(clientData)).append("</CipherValue></CipherData>")
        append("</EncryptedData>")
        append("</LA>")
    }

    private fun buildSignedInfo(digest: ByteArray): String = buildString {
        append("<SignedInfo xmlns=\"").append(XMLDSIG_NS).append("\">")
        append("<CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\">")
        append("</CanonicalizationMethod>")
        append("<SignatureMethod Algorithm=\"").append(PROTOCOLS_NS).append("#ecdsa-sha256\"></SignatureMethod>")
        append("<Reference URI=\"#SignedData\">")
        append("<DigestMethod Algorithm=\"").append(PROTOCOLS_NS).append("#sha256\"></DigestMethod>")
        append("<DigestValue>").append(Base64.encode(digest)).append("</DigestValue>")
        append("</Reference>")
        append("</SignedInfo>")
    }

    /**
     * The client's certificate chain and feature list, AES-CBC encrypted under the session key.
     *
     * The IV is prepended to the ciphertext; the server recovers the key by ElGamal-decrypting the
     * session point it was sent alongside.
     */
    private suspend fun encryptClientData(certificateChain: CertificateChain, xmlKey: XmlKey): ByteArray {
        val plaintext = buildString {
            append("<Data>")
            // The spaces around the Base64 are part of the format, not incidental whitespace.
            append("<CertificateChains><CertificateChain> ")
            append(certificateChain.dumpsBase64())
            append(" </CertificateChain></CertificateChains>")
            append("<Features>")
            append("<Feature Name=\"AESCBC\"></Feature>")
            append("<REE><AESCBCS></AESCBCS></REE>")
            append("</Features>")
            append("</Data>")
        }

        val ciphertext = aesCbcEncryptNoPadding(xmlKey.key, xmlKey.iv, pkcs7Pad(plaintext.encodeToByteArray()))
        return xmlKey.iv + ciphertext
    }

    private fun escape(value: String): String = buildString(value.length) {
        for (c in value) {
            when (c) {
                '&' -> append("&amp;")
                '<' -> append("&lt;")
                '>' -> append("&gt;")
                '"' -> append("&quot;")
                else -> append(c)
            }
        }
    }
}

/**
 * The per-session key a challenge carries to the license server.
 *
 * It is an ephemeral P-256 key pair whose public X coordinate doubles as AES material: the high
 * 16 bytes are the IV, the low 16 the key. The whole point is ElGamal-encrypted to the server's
 * WMRM key, which is how the server derives the same pair.
 */
internal class XmlKey private constructor(
    val point: EcPoint,
    val iv: ByteArray,
    val key: ByteArray,
) {
    companion object {
        fun generate(): XmlKey {
            val point = P256.publicPoint(ElGamal.randomScalar())
            val x = P256.toFixed32(point.x)
            return XmlKey(point, x.copyOfRange(0, 16), x.copyOfRange(16, 32))
        }
    }
}
