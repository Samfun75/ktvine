@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktvine.core

import nl.adaptivity.xmlutil.EventType
import nl.adaptivity.xmlutil.allText
import nl.adaptivity.xmlutil.xmlStreaming
import org.samfun.ktvine.utils.DecodeException
import org.samfun.ktvine.utils.toUUID
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Pulls PSSH boxes out of DASH and HLS manifests.
 *
 * This is a convenience layer — nothing here talks to the network, and a manifest is not
 * required to use [Cdm]. It exists because "find the init data in this manifest" is the
 * step every caller has to write otherwise, and doing it with a regex is where people go
 * wrong.
 */
public object Manifests {

    /** `urn:uuid:` form of a DRM system id, as `ContentProtection@schemeIdUri` spells it. */
    private fun schemeIdUriOf(systemId: ByteArray): String = "urn:uuid:${systemId.toUUID()}"

    /**
     * Every PSSH declared for [systemId] in a DASH MPD, in document order and de-duplicated.
     *
     * Reads `ContentProtection` elements whose `schemeIdUri` matches, taking the init data
     * from a `cenc:pssh` child, or from an `mspr:pro` child for PlayReady. Manifests
     * normally repeat the same `ContentProtection` on every AdaptationSet, so identical
     * boxes are collapsed.
     *
     * @throws DecodeException if the document is not well-formed XML
     */
    public fun psshFromMpd(xml: String, systemId: ByteArray = PSSH.WIDEVINE): List<PSSH> {
        val wanted = schemeIdUriOf(systemId).lowercase()
        val found = LinkedHashMap<String, PSSH>()

        forEachContentProtection(xml) { scheme, childName, text ->
            if (scheme != wanted) return@forEachContentProtection
            val pssh = when (childName) {
                // A cenc:pssh is a full box; an mspr:pro is a bare PlayReady Object, which
                // the PSSH cascade wraps for us.
                "PSSH", "PRO" -> runCatching { PSSH(text) }.getOrNull()
                else -> null
            } ?: return@forEachContentProtection
            found.getOrPut(pssh.exportBase64()) { pssh }
        }

        return found.values.toList()
    }

    /**
     * The `cenc:default_KID` values declared in a DASH MPD, de-duplicated.
     *
     * Useful as an independent cross-check of what a PSSH claims — the two disagreeing is
     * usually a sign the PSSH was parsed wrong.
     *
     * @throws DecodeException if the document is not well-formed XML
     */
    public fun defaultKeyIdsFromMpd(xml: String): List<Uuid> {
        val found = LinkedHashSet<Uuid>()
        val reader = readerFor(xml)

        try {
            while (reader.hasNext()) {
                if (reader.next() != EventType.START_ELEMENT) continue
                if (!reader.localName.equals("ContentProtection", ignoreCase = true)) continue
                for (i in 0 until reader.attributeCount) {
                    if (!reader.getAttributeLocalName(i).equals("default_KID", ignoreCase = true)) continue
                    runCatching { Uuid.parse(reader.getAttributeValue(i).trim()) }.getOrNull()?.let { found += it }
                }
            }
        } catch (e: Throwable) {
            throw DecodeException("Could not read the MPD, $e")
        }

        return found.toList()
    }

    /**
     * Every PSSH carried inline by an HLS playlist, in document order and de-duplicated.
     *
     * Reads `#EXT-X-KEY` and `#EXT-X-SESSION-KEY` tags whose `URI` is a
     * `data:text/plain;base64,…` payload, filtered by `KEYFORMAT` when [systemId] is given.
     * Tags pointing at an external URI are skipped — fetching them is the caller's job.
     */
    public fun psshFromM3u8(playlist: String, systemId: ByteArray? = PSSH.WIDEVINE): List<PSSH> {
        val wanted = systemId?.let { schemeIdUriOf(it).lowercase() }
        val found = LinkedHashMap<String, PSSH>()

        for (rawLine in playlist.lineSequence()) {
            val line = rawLine.trim()
            val attributes = when {
                line.startsWith("#EXT-X-KEY:") -> parseAttributeList(line.removePrefix("#EXT-X-KEY:"))
                line.startsWith("#EXT-X-SESSION-KEY:") -> parseAttributeList(line.removePrefix("#EXT-X-SESSION-KEY:"))
                else -> continue
            }

            if (attributes["METHOD"].equals("NONE", ignoreCase = true)) continue
            if (wanted != null && attributes["KEYFORMAT"]?.lowercase() != wanted) continue

            val uri = attributes["URI"] ?: continue
            val payload = uri.substringAfter("base64,", missingDelimiterValue = "")
            if (payload.isEmpty()) continue

            val pssh = runCatching { PSSH(payload) }.getOrNull() ?: continue
            found.getOrPut(pssh.exportBase64()) { pssh }
        }

        return found.values.toList()
    }

    private fun readerFor(xml: String) = try {
        xmlStreaming.newReader(xml)
    } catch (e: Throwable) {
        throw DecodeException("Manifest is not well-formed XML, $e")
    }

    /**
     * Visit every direct child element of a `ContentProtection`, with that element's
     * `schemeIdUri` (lowercased), the child's local name (uppercased) and its text.
     */
    private inline fun forEachContentProtection(
        xml: String,
        onChild: (scheme: String, childName: String, text: String) -> Unit,
    ) {
        val reader = readerFor(xml)
        var scheme: String? = null
        var depth = 0

        try {
            while (reader.hasNext()) {
                when (reader.next()) {
                    EventType.START_ELEMENT -> {
                        if (reader.localName.equals("ContentProtection", ignoreCase = true)) {
                            scheme = reader.getAttributeValue(null, "schemeIdUri")?.trim()?.lowercase()
                            depth = 0
                        } else if (scheme != null) {
                            depth++
                            if (depth == 1) {
                                val name = reader.localName.uppercase()
                                val text = reader.allText().trim()
                                // allText consumed the end element, so this child is closed.
                                depth--
                                if (text.isNotEmpty()) onChild(scheme, name, text)
                            }
                        }
                    }

                    EventType.END_ELEMENT -> {
                        if (reader.localName.equals("ContentProtection", ignoreCase = true)) {
                            scheme = null
                            depth = 0
                        } else if (scheme != null && depth > 0) {
                            depth--
                        }
                    }

                    else -> Unit
                }
            }
        } catch (e: Throwable) {
            throw DecodeException("Could not read the MPD, $e")
        }
    }

    /**
     * Split an HLS attribute list. Values may be quoted and quoted values may contain
     * commas, so this cannot be a plain `split(',')`.
     */
    private fun parseAttributeList(input: String): Map<String, String> {
        val attributes = LinkedHashMap<String, String>()
        var index = 0

        while (index < input.length) {
            val equals = input.indexOf('=', index)
            if (equals < 0) break
            val name = input.substring(index, equals).trim()

            var cursor = equals + 1
            val value: String
            if (cursor < input.length && input[cursor] == '"') {
                val close = input.indexOf('"', cursor + 1)
                if (close < 0) break
                value = input.substring(cursor + 1, close)
                cursor = close + 1
            } else {
                val comma = input.indexOf(',', cursor).let { if (it < 0) input.length else it }
                value = input.substring(cursor, comma).trim()
                cursor = comma
            }

            if (name.isNotEmpty()) attributes[name.uppercase()] = value
            index = if (cursor < input.length && input[cursor] == ',') cursor + 1 else cursor + 1
        }

        return attributes
    }
}
