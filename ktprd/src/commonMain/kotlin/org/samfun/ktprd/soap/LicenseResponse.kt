package org.samfun.ktprd.soap

import nl.adaptivity.xmlutil.EventType
import nl.adaptivity.xmlutil.XmlReader
import nl.adaptivity.xmlutil.allText
import nl.adaptivity.xmlutil.xmlStreaming
import org.samfun.ktprd.bcert.BCertKeyUsage
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.crypto.sha256
import org.samfun.ktprd.utils.InvalidLicenseResponseException
import org.samfun.ktprd.xmr.XmrLicense
import org.samfun.ktvine.crypto.constantTimeEquals
import kotlin.io.encoding.Base64

/**
 * A parsed `AcquireLicenseResponse`.
 *
 * The response signs two of its own elements, and both digests cover the bytes as received. That
 * is why [elementSource] slices the original document by offset rather than letting the parser
 * hand back a re-serialization: any difference in attribute order, namespace prefix or whitespace
 * would change the hash without changing the meaning.
 */
public class LicenseResponse internal constructor(
    private val document: String,
    /** The base64 XMR licenses the response carries, in order. */
    public val licenses: List<String>,
    public val signingCertificateChain: CertificateChain?,
    public val licenseNonce: String?,
    public val responseId: String?,
    public val transactionId: String?,
    /** The `RevInfo` element verbatim, when the server sent updated revocation data. */
    public val revocationInfo: String?,
    private val digestValue: String?,
    private val signatureValue: String?,
    private val licenseResponseRange: IntRange?,
    private val signedInfoRange: IntRange?,
) {
    /** The XMR licenses, decoded. */
    public fun xmrLicenses(): List<XmrLicense> = licenses.map { XmrLicense.loads(it) }

    /** Whether the response carries everything needed for [verify] to mean anything. */
    public val isVerifiable: Boolean
        get() = signingCertificateChain != null &&
            digestValue != null &&
            signatureValue != null &&
            licenseResponseRange != null &&
            signedInfoRange != null

    /**
     * Check that the response really came from the server whose certificate it names.
     *
     * Two steps: the declared digest must match a SHA-256 of the `LicenseResponse` element as
     * received, and the signature over the `SignedInfo` element must verify under the signing
     * certificate's `SIGN_RESPONSE` key.
     *
     * @throws InvalidLicenseResponseException if either fails, or if the response is not verifiable
     */
    public suspend fun verify() {
        if (!isVerifiable) {
            throw InvalidLicenseResponseException("License response carries no signature to verify")
        }

        val expectedDigest = try {
            Base64.decode(digestValue!!.trim())
        } catch (e: Throwable) {
            throw InvalidLicenseResponseException("DigestValue is not valid Base64, $e")
        }

        val actualDigest = sha256(document.substring(licenseResponseRange!!).encodeToByteArray())
        if (!constantTimeEquals(expectedDigest, actualDigest)) {
            throw InvalidLicenseResponseException("License response digest does not match its own content")
        }

        val chain = signingCertificateChain!!
        val signingKey = chain.get(0).keyByUsage(BCertKeyUsage.SIGN_RESPONSE)
            ?: throw InvalidLicenseResponseException("Signing certificate declares no response-signing key")

        val signature = try {
            Base64.decode(signatureValue!!.trim())
        } catch (e: Throwable) {
            throw InvalidLicenseResponseException("SignatureValue is not valid Base64, $e")
        }

        val signedInfo = document.substring(signedInfoRange!!).encodeToByteArray()
        if (!Ecdsa.verify(signingKey, signedInfo, signature)) {
            throw InvalidLicenseResponseException("License response signature is not authentic")
        }
    }

    override fun toString(): String = "LicenseResponse(${licenses.size} licenses, verifiable=$isVerifiable)"

    public companion object {
        /**
         * Parse a license response out of a SOAP envelope.
         *
         * @throws InvalidLicenseResponseException if the document is not an `AcquireLicenseResponse`
         */
        public fun parse(document: String): LicenseResponse {
            val reader = try {
                xmlStreaming.newReader(document)
            } catch (e: Throwable) {
                throw InvalidLicenseResponseException("License response is not well-formed XML, $e")
            }

            val licenses = mutableListOf<String>()
            var chainText: String? = null
            var licenseNonce: String? = null
            var responseId: String? = null
            var transactionId: String? = null
            var digestValue: String? = null
            var signatureValue: String? = null
            var sawResponse = false

            val path = ArrayDeque<String>()

            try {
                while (reader.hasNext()) {
                    when (reader.next()) {
                        EventType.START_ELEMENT -> {
                            path.addLast(reader.localName)
                            var consumed = true
                            when (reader.localName) {
                                "AcquireLicenseResponse" -> {
                                    sawResponse = true
                                    consumed = false
                                }

                                "License" -> reader.textOrNull()?.let { licenses += it }
                                "SigningCertificateChain" -> chainText = reader.textOrNull()
                                "LicenseNonce" -> licenseNonce = reader.textOrNull()
                                "ResponseID" -> responseId = reader.textOrNull()
                                "TransactionID" -> transactionId = reader.textOrNull()
                                "DigestValue" -> digestValue = reader.textOrNull()
                                "SignatureValue" -> signatureValue = reader.textOrNull()
                                else -> consumed = false
                            }
                            if (consumed) path.removeLast()
                        }

                        EventType.END_ELEMENT -> path.removeLastOrNull()
                        else -> Unit
                    }
                }
            } catch (e: Throwable) {
                throw InvalidLicenseResponseException("License response could not be parsed, $e")
            }

            if (!sawResponse) {
                throw InvalidLicenseResponseException("License response is not an AcquireLicenseResponse")
            }

            val chain = chainText?.let {
                try {
                    CertificateChain.loads(it)
                } catch (e: Throwable) {
                    throw InvalidLicenseResponseException("SigningCertificateChain could not be parsed, ${e.message}")
                }
            }

            return LicenseResponse(
                document = document,
                licenses = licenses,
                signingCertificateChain = chain,
                licenseNonce = licenseNonce,
                responseId = responseId,
                transactionId = transactionId,
                revocationInfo = elementSource(document, "RevInfo")?.let { document.substring(it) },
                digestValue = digestValue,
                signatureValue = signatureValue,
                licenseResponseRange = elementSource(document, "LicenseResponse"),
                signedInfoRange = elementSource(document, "SignedInfo"),
            )
        }

        /**
         * The character range an element occupies in [document], including its own tags.
         *
         * Located by scanning the text rather than by re-serializing a parse, because the two
         * digests in a response are taken over exactly these bytes. Namespace prefixes are matched
         * loosely: a server may write `LicenseResponse` or `proto:LicenseResponse` for the same
         * element, and both must resolve to the same span.
         */
        internal fun elementSource(document: String, localName: String): IntRange? {
            val start = findOpeningTag(document, localName) ?: return null
            val end = findClosingTag(document, localName, start) ?: return null
            return start until end
        }

        private fun findOpeningTag(document: String, localName: String): Int? {
            var index = 0
            while (true) {
                index = document.indexOf("<", index).takeIf { it >= 0 } ?: return null
                val nameStart = index + 1
                if (nameStart < document.length && (document[nameStart] == '/' || document[nameStart] == '?')) {
                    index = nameStart
                    continue
                }
                val nameEnd = document.indexOfFirst(nameStart) { it.isWhitespace() || it == '>' || it == '/' }
                    ?: return null
                val qualified = document.substring(nameStart, nameEnd)
                if (qualified.substringAfterLast(':') == localName) return index
                index = nameEnd
            }
        }

        private fun findClosingTag(document: String, localName: String, from: Int): Int? {
            var index = from
            while (true) {
                index = document.indexOf("</", index).takeIf { it >= 0 } ?: return null
                val nameStart = index + 2
                val nameEnd = document.indexOfFirst(nameStart) { it.isWhitespace() || it == '>' } ?: return null
                if (document.substring(nameStart, nameEnd).substringAfterLast(':') == localName) {
                    val close = document.indexOf('>', nameEnd)
                    return if (close < 0) null else close + 1
                }
                index = nameStart
            }
        }

        private inline fun String.indexOfFirst(from: Int, predicate: (Char) -> Boolean): Int? {
            for (i in from until length) if (predicate(this[i])) return i
            return null
        }

        private fun XmlReader.textOrNull(): String? = allText().trim().takeIf { it.isNotEmpty() }
    }
}
