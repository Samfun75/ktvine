package org.samfun.ktprd.soap

import nl.adaptivity.xmlutil.EventType
import nl.adaptivity.xmlutil.XmlReader
import nl.adaptivity.xmlutil.allText
import nl.adaptivity.xmlutil.xmlStreaming
import org.samfun.ktprd.utils.DrmResult
import org.samfun.ktprd.utils.InvalidSoapMessageException
import org.samfun.ktprd.utils.PlayreadyServerException

/**
 * The SOAP envelope a PlayReady license exchange travels in.
 *
 * Only two things are needed here: wrap an outgoing challenge, and recognise an incoming fault so
 * a server rejection surfaces as a typed error rather than a parse failure further down.
 */
internal object SoapMessage {

    private const val DECLARATION = "<?xml version=\"1.0\" encoding=\"utf-8\"?>"

    /** Wrap a message element in a SOAP 1.1 envelope. */
    fun wrap(message: String): String = buildString {
        append(DECLARATION)
        append("<soap:Envelope xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"")
        append(" xmlns:xsd=\"http://www.w3.org/2001/XMLSchema\"")
        append(" xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\">")
        append("<soap:Body>")
        append(message)
        append("</soap:Body>")
        append("</soap:Envelope>")
    }

    /**
     * Throw if [document] is a SOAP fault.
     *
     * The status code a fault carries is a `DRM_RESULT`, so it is mapped to a name before being
     * reported — "the request was rejected" is not an actionable message on its own.
     *
     * @throws PlayreadyServerException if the response body is a fault
     * @throws InvalidSoapMessageException if it is not a SOAP envelope at all
     */
    fun raiseFaults(document: String) {
        val reader = try {
            xmlStreaming.newReader(document)
        } catch (e: Throwable) {
            throw InvalidSoapMessageException("License response is not well-formed XML, $e")
        }

        var sawEnvelope = false
        var isFault = false
        var statusCode: String? = null
        var faultString: String? = null
        var reasonText: String? = null
        val path = ArrayDeque<String>()

        try {
            while (reader.hasNext()) {
                when (reader.next()) {
                    EventType.START_ELEMENT -> {
                        path.addLast(reader.localName)
                        when (reader.localName) {
                            "Envelope" -> sawEnvelope = true
                            "Fault" -> if (path.size == 3) isFault = true
                            "StatusCode" -> statusCode = reader.textOrNull().also { path.removeLast() }
                            "faultstring" -> faultString = reader.textOrNull().also { path.removeLast() }
                            "Text" -> reasonText = reader.textOrNull().also { path.removeLast() }
                        }
                    }

                    EventType.END_ELEMENT -> path.removeLastOrNull()
                    else -> Unit
                }
            }
        } catch (e: Throwable) {
            throw InvalidSoapMessageException("License response could not be parsed, $e")
        }

        if (!sawEnvelope) throw InvalidSoapMessageException("License response is not a SOAP envelope")
        if (!isFault) return

        val result = statusCode?.let { DrmResult.fromCode(it) }
        val message = faultString ?: reasonText ?: result?.message ?: "the server gave no reason"
        throw PlayreadyServerException(
            if (result != null) "[${result.name}] $message" else message,
            result?.code,
        )
    }

    private fun XmlReader.textOrNull(): String? = allText().trim().takeIf { it.isNotEmpty() }
}
