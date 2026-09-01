@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine.core

import nl.adaptivity.xmlutil.EventType
import nl.adaptivity.xmlutil.XmlReader
import nl.adaptivity.xmlutil.allText
import nl.adaptivity.xmlutil.xmlStreaming
import org.samfun.ktvine.utils.ValueException
import org.samfun.ktvine.utils.toLittleEndianByteArray
import org.samfun.ktvine.utils.uuidFromLittleEndian
import kotlin.io.encoding.Base64
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * A parsed PlayReady `WRMHEADER`.
 *
 * Key ids are held big-endian, matching `cenc:default_KID` and Widevine; the little-endian
 * GUID form the header stores is converted on the way in and out.
 */
internal data class PlayreadyHeader(
    val version: String,
    val keyIds: List<Uuid>,
    val algid: String? = null,
    val laUrl: String? = null,
    val luiUrl: String? = null,
    val dsId: ByteArray? = null,
    val decryptorSetup: String? = null,
    val customAttributes: String? = null,
) {
    // dsId is a ByteArray, so the generated data-class implementations would be wrong.
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PlayreadyHeader) return false
        return version == other.version &&
            keyIds == other.keyIds &&
            algid == other.algid &&
            laUrl == other.laUrl &&
            luiUrl == other.luiUrl &&
            (dsId?.contentEquals(other.dsId) ?: (other.dsId == null)) &&
            decryptorSetup == other.decryptorSetup &&
            customAttributes == other.customAttributes
    }

    override fun hashCode(): Int {
        var result = version.hashCode()
        result = 31 * result + keyIds.hashCode()
        result = 31 * result + (algid?.hashCode() ?: 0)
        result = 31 * result + (laUrl?.hashCode() ?: 0)
        result = 31 * result + (luiUrl?.hashCode() ?: 0)
        result = 31 * result + (dsId?.contentHashCode() ?: 0)
        result = 31 * result + (decryptorSetup?.hashCode() ?: 0)
        result = 31 * result + (customAttributes?.hashCode() ?: 0)
        return result
    }

    internal companion object {
        const val NAMESPACE: String = "http://schemas.microsoft.com/DRM/2007/03/PlayReadyHeader"

        /** The version this library emits. */
        const val GENERATED_VERSION: String = "4.3.0.0"

        private val SUPPORTED = setOf("4.0.0.0", "4.1.0.0", "4.2.0.0", "4.3.0.0")

        /**
         * Parse a `WRMHEADER` document.
         *
         * Each version puts key ids somewhere different, and this enforces the right path
         * rather than accepting a `<KID>` anywhere in the document:
         *
         * | Version           | Key ids                                  |
         * |-------------------|------------------------------------------|
         * | 4.0.0.0           | `DATA/KID` element text                  |
         * | 4.1.0.0           | `DATA/PROTECTINFO/KID` `VALUE` attribute |
         * | 4.2.0.0, 4.3.0.0  | `DATA/PROTECTINFO/KIDS/KID` `VALUE` attr |
         *
         * @throws ValueException if the document is not a supported `WRMHEADER`
         */
        fun parse(xml: String): PlayreadyHeader {
            val reader = try {
                xmlStreaming.newReader(xml)
            } catch (e: Throwable) {
                throw ValueException("PlayReadyHeader is not well-formed XML, $e")
            }

            var version: String? = null
            val keyIds = mutableListOf<Uuid>()
            var algid: String? = null
            var laUrl: String? = null
            var luiUrl: String? = null
            var dsId: ByteArray? = null
            var decryptorSetup: String? = null
            var customAttributes: String? = null

            val path = ArrayDeque<String>()

            try {
                while (reader.hasNext()) {
                    when (reader.next()) {
                        EventType.START_ELEMENT -> {
                            path.addLast(reader.localName.uppercase())
                            val here = path.joinToString("/")

                            when (here) {
                                "WRMHEADER" -> {
                                    version = reader.getAttributeValue(null, "version")
                                        ?: throw ValueException("WRMHEADER has no version attribute")
                                }

                                // 4.1.0.0 and 4.2.0.0+ carry the id in a VALUE attribute.
                                "WRMHEADER/DATA/PROTECTINFO/KID",
                                "WRMHEADER/DATA/PROTECTINFO/KIDS/KID",
                                -> {
                                    val expected = when (version) {
                                        "4.1.0.0" -> "WRMHEADER/DATA/PROTECTINFO/KID"
                                        "4.2.0.0", "4.3.0.0" -> "WRMHEADER/DATA/PROTECTINFO/KIDS/KID"
                                        else -> null
                                    }
                                    if (here == expected) {
                                        reader.getAttributeValue(null, "ALGID")?.let { if (algid == null) algid = it }
                                        val value = reader.getAttributeValue(null, "VALUE")
                                            ?: throw ValueException("A <KID> in a v$version header has no VALUE")
                                        keyIds += decodeKid(value)
                                    }
                                }

                                "WRMHEADER/DATA/PROTECTINFO/ALGID" ->
                                    reader.readText()?.let { if (algid == null) algid = it }

                                // 4.0.0.0 puts a single id in the element text.
                                "WRMHEADER/DATA/KID" ->
                                    if (version == "4.0.0.0") {
                                        reader.readText()?.let { keyIds += decodeKid(it) }
                                    }

                                "WRMHEADER/DATA/LA_URL" -> laUrl = reader.readText()
                                "WRMHEADER/DATA/LUI_URL" -> luiUrl = reader.readText()
                                "WRMHEADER/DATA/DS_ID" -> dsId = reader.readText()?.let { Base64.decode(it) }
                                "WRMHEADER/DATA/DECRYPTORSETUP" -> decryptorSetup = reader.readText()
                                "WRMHEADER/DATA/CUSTOMATTRIBUTES" ->
                                    customAttributes = readInnerXml(reader).takeIf { it.isNotBlank() }
                            }

                            // readText/readInnerXml consume through the end element themselves.
                            if (path.lastOrNull()?.let { consumesElement(path.joinToString("/"), version) } == true) {
                                path.removeLast()
                            }
                        }

                        EventType.END_ELEMENT -> path.removeLastOrNull()

                        else -> Unit
                    }
                }
            } catch (e: ValueException) {
                throw e
            } catch (e: Throwable) {
                throw ValueException("PlayReadyHeader could not be parsed, $e")
            }

            val resolved = version ?: throw ValueException("Unsupported PlayReadyHeader, missing version")
            if (resolved !in SUPPORTED) throw ValueException("Unsupported PlayReadyHeader version $resolved")

            return PlayreadyHeader(
                version = resolved,
                keyIds = keyIds,
                algid = algid,
                laUrl = laUrl,
                luiUrl = luiUrl,
                dsId = dsId,
                decryptorSetup = decryptorSetup,
                customAttributes = customAttributes,
            )
        }

        /** Elements whose handler above already consumed the matching end tag. */
        private fun consumesElement(path: String, version: String?): Boolean = when (path) {
            "WRMHEADER/DATA/PROTECTINFO/ALGID",
            "WRMHEADER/DATA/LA_URL",
            "WRMHEADER/DATA/LUI_URL",
            "WRMHEADER/DATA/DS_ID",
            "WRMHEADER/DATA/DECRYPTORSETUP",
            "WRMHEADER/DATA/CUSTOMATTRIBUTES",
            -> true

            "WRMHEADER/DATA/KID" -> version == "4.0.0.0"
            else -> false
        }

        private fun decodeKid(value: String): Uuid {
            val bytes = try {
                Base64.decode(value.trim())
            } catch (e: Throwable) {
                throw ValueException("A <KID> value is not valid Base64, $e")
            }
            if (bytes.size != 16) throw ValueException("A <KID> value is ${bytes.size} bytes, expected 16")
            return bytes.uuidFromLittleEndian()
        }

        /** Text of the current element, or `null` when it is empty. Consumes the end tag. */
        private fun XmlReader.readText(): String? {
            val text = allText().trim()
            return text.takeIf { it.isNotEmpty() }
        }

        /** The current element's children, re-serialized. Consumes the end tag. */
        private fun readInnerXml(reader: XmlReader): String = buildString {
            var depth = 0
            while (reader.hasNext()) {
                when (reader.next()) {
                    EventType.START_ELEMENT -> {
                        depth++
                        append('<').append(reader.localName)
                        for (i in 0 until reader.attributeCount) {
                            append(' ').append(reader.getAttributeLocalName(i))
                                .append("=\"").append(escape(reader.getAttributeValue(i))).append('"')
                        }
                        append('>')
                    }

                    EventType.END_ELEMENT -> {
                        if (depth == 0) return@buildString
                        depth--
                        append("</").append(reader.localName).append('>')
                    }

                    EventType.TEXT, EventType.CDSECT -> append(escape(reader.text))
                    else -> Unit
                }
            }
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

        /**
         * Serialize a v4.3.0.0 `WRMHEADER`.
         *
         * Output is deterministic: fixed element order, no insignificant whitespace, and
         * every interpolated value escaped.
         */
        fun build(
            keyIds: List<Uuid>,
            algid: String,
            laUrl: String? = null,
            luiUrl: String? = null,
            dsId: ByteArray? = null,
            decryptorSetup: String? = null,
            customAttributes: String? = null,
        ): String = buildString {
            append("<WRMHEADER xmlns=\"").append(escape(NAMESPACE))
            append("\" version=\"").append(GENERATED_VERSION).append("\">")
            append("<DATA>")
            append("<PROTECTINFO><KIDS>")
            keyIds.forEach { kid ->
                append("<KID ALGID=\"").append(escape(algid))
                append("\" VALUE=\"").append(Base64.encode(kid.toLittleEndianByteArray())).append("\"></KID>")
            }
            append("</KIDS></PROTECTINFO>")
            laUrl?.let { append("<LA_URL>").append(escape(it)).append("</LA_URL>") }
            luiUrl?.let { append("<LUI_URL>").append(escape(it)).append("</LUI_URL>") }
            dsId?.let { append("<DS_ID>").append(Base64.encode(it)).append("</DS_ID>") }
            decryptorSetup?.let { append("<DECRYPTORSETUP>").append(escape(it)).append("</DECRYPTORSETUP>") }
            // Raw by spec: the content author supplies XML here, so it is passed through.
            customAttributes?.let { append("<CUSTOMATTRIBUTES xmlns=\"\">").append(it).append("</CUSTOMATTRIBUTES>") }
            append("</DATA>")
            append("</WRMHEADER>")
        }
    }
}
