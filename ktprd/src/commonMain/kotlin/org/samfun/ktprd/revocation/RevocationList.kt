@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd.revocation

import nl.adaptivity.xmlutil.EventType
import nl.adaptivity.xmlutil.XmlReader
import nl.adaptivity.xmlutil.allText
import nl.adaptivity.xmlutil.xmlStreaming
import org.samfun.ktprd.bcert.BCertKeyUsage
import org.samfun.ktprd.bcert.BCertType
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.crypto.Ecdsa
import org.samfun.ktprd.utils.ByteReader
import org.samfun.ktprd.utils.InvalidRevocationListException
import org.samfun.ktvine.utils.toLittleEndianByteArray
import org.samfun.ktvine.utils.uuidFromLittleEndian
import kotlin.io.encoding.Base64
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/** One revocation list inside a `RevInfo` document. */
public class RevocationEntry internal constructor(
    public val listId: Uuid,
    /** The version this list declares, which is what a challenge advertises back. */
    public val version: Long,
    /** The Base64 payload as received, so it can be stored and re-sent verbatim. */
    public val listData: String,
    /**
     * Whether ktprd checked this list's signature.
     *
     * False for the legacy WMDRM network list, whose signature uses a 160-bit Microsoft curve that
     * no public implementation is known to verify successfully. Such a list is parsed for its
     * version but never presented as authenticated.
     */
    public val verified: Boolean,
)

/**
 * A PlayReady `RevInfo` document — the revocation data a license server sends alongside a license.
 *
 * A client advertises the versions it already holds in its next challenge, and a server that has
 * newer ones sends them back. Keeping them is optional but a server may refuse a client that
 * claims nothing.
 */
public class RevocationList internal constructor(
    public val entries: List<RevocationEntry>,
) {
    public fun entry(listId: Uuid): RevocationEntry? = entries.firstOrNull { it.listId == listId }

    /** The version of [listId] this document declares, or `0` when it declares none. */
    public fun versionOf(listId: Uuid): Long = entry(listId)?.version ?: 0

    override fun toString(): String = "RevocationList(${entries.map { it.listId }})"

    public companion object {
        /** The file name a current `RevInfo` document is kept under. */
        public const val CURRENT_LIST_FILE_NAME: String = "RevInfo_Current.xml"

        /** Revocation information, version 1. */
        public val REV_INFO: Uuid = Uuid.parse("ccde5a55-a688-4405-a88b-d13f90d5ba3e")

        /** Revocation information, version 2. */
        public val REV_INFO_V2: Uuid = Uuid.parse("52d1ff11-d388-4edd-82b7-68ea4c20a16c")

        /** Revoked PlayReady runtimes. */
        public val PLAYREADY_RUNTIME: Uuid = Uuid.parse("4e9d8c8a-b652-45a7-9791-6925a6b4791f")

        /** Revoked PlayReady applications. */
        public val PLAYREADY_APPLICATION: Uuid = Uuid.parse("28082e80-c7a3-40b1-8256-19e5b6d89b27")

        /** The legacy Windows Media DRM network list. */
        public val WMDRM_NETWORK: Uuid = Uuid.parse("cd75e604-543d-4a9c-9f09-fe6d24e8bf90")

        /** Revoked WMDRM devices. */
        public val DEVICE_REVOCATION: Uuid = Uuid.parse("3129e375-ceb0-47d5-9cca-9db74cfd4332")

        /** Revoked applications. */
        public val APP_REVOCATION: Uuid = Uuid.parse("90a37313-0ecf-4caa-a906-b188f6129300")

        /** The lists a client normally advertises. */
        public val SUPPORTED_LIST_IDS: List<Uuid> =
            listOf(PLAYREADY_RUNTIME, PLAYREADY_APPLICATION, REV_INFO_V2, WMDRM_NETWORK)

        private const val MAGIC_RLVI = 0x524C5649L
        private const val MAGIC_RLV2 = 0x524C5632L

        /** A revocation payload may carry a bare 64-byte signing key instead of a chain. */
        private const val BARE_PUBLIC_KEY_SIZE = 64

        /**
         * Parse a `RevInfo` document, verifying each list it can.
         *
         * @param verify check each list's signature; a list that fails is rejected outright rather
         *   than being kept unauthenticated
         * @throws InvalidRevocationListException if the document is not a `RevInfo`, or a list
         *   fails verification
         */
        public suspend fun parse(document: String, verify: Boolean = true): RevocationList {
            val raw = parseWrapper(document)
            return RevocationList(raw.map { (listId, listData) -> parseEntry(listId, listData, verify) })
        }

        /** Parse a `RevInfo` document from bytes, stripping a UTF-8 byte-order mark. */
        public suspend fun parse(document: ByteArray, verify: Boolean = true): RevocationList =
            parse(stripBom(document).decodeToString(), verify)

        /**
         * The version of [listId] declared by a stored `RevInfo` document, or `0`.
         *
         * Signatures are not checked here: this only reads back what this client previously stored,
         * and a challenge that advertises a stale version is refused by the server, not exploited.
         */
        public suspend fun versionOf(document: ByteArray, listId: Uuid): Long = try {
            parse(document, verify = false).versionOf(listId)
        } catch (e: InvalidRevocationListException) {
            0
        }

        /**
         * Merge [incoming] into [current], keeping whichever version of each list is newer.
         *
         * @return the merged document
         */
        public suspend fun merge(current: String, incoming: String): String {
            val currentEntries = parseWrapper(current).associate { (id, data) -> id to data }.toMutableMap()
            val currentVersions = parse(current, verify = false).entries.associate { it.listId to it.version }

            for ((listId, data) in parseWrapper(incoming)) {
                val newVersion = runCatching { parseEntry(listId, data, verify = false).version }.getOrDefault(0)
                if (listId !in currentEntries || newVersion > (currentVersions[listId] ?: 0)) {
                    currentEntries[listId] = data
                }
            }

            return buildString {
                append("<RevInfo>")
                for ((listId, data) in currentEntries) {
                    append("<Revocation>")
                    append("<ListID>").append(Base64.encode(listId.toLittleEndianByteArray())).append("</ListID>")
                    append("<ListData>").append(data).append("</ListData>")
                    append("</Revocation>")
                }
                append("</RevInfo>")
            }
        }

        private fun stripBom(data: ByteArray): ByteArray =
            if (data.size >= 3 && data[0] == 0xEF.toByte() && data[1] == 0xBB.toByte() && data[2] == 0xBF.toByte()) {
                data.copyOfRange(3, data.size)
            } else {
                data
            }

        /** The `(listId, base64 payload)` pairs a `RevInfo` document carries. */
        private fun parseWrapper(document: String): List<Pair<Uuid, String>> {
            val reader = try {
                xmlStreaming.newReader(document)
            } catch (e: Throwable) {
                throw InvalidRevocationListException("RevInfo is not well-formed XML, $e")
            }

            var sawRoot = false
            var listId: Uuid? = null
            val entries = mutableListOf<Pair<Uuid, String>>()

            try {
                while (reader.hasNext()) {
                    if (reader.next() != EventType.START_ELEMENT) continue
                    when (reader.localName) {
                        "RevInfo" -> sawRoot = true
                        "ListID" -> listId = reader.textOrNull()?.let { decodeListId(it) }
                        "ListData" -> reader.textOrNull()?.let { data ->
                            listId?.let { entries += it to data }
                            listId = null
                        }
                    }
                }
            } catch (e: Throwable) {
                throw InvalidRevocationListException("RevInfo could not be parsed, $e")
            }

            if (!sawRoot) throw InvalidRevocationListException("Root element is not RevInfo")
            return entries
        }

        private fun decodeListId(value: String): Uuid {
            val bytes = try {
                Base64.decode(value.trim())
            } catch (e: Throwable) {
                throw InvalidRevocationListException("A ListID is not valid Base64, $e")
            }
            if (bytes.size != 16) throw InvalidRevocationListException("A ListID is ${bytes.size} bytes, expected 16")
            return bytes.uuidFromLittleEndian()
        }

        private suspend fun parseEntry(listId: Uuid, listData: String, verify: Boolean): RevocationEntry {
            val payload = try {
                Base64.decode(listData.trim())
            } catch (e: Throwable) {
                throw InvalidRevocationListException("ListData for $listId is not valid Base64, $e")
            }

            return when (listId) {
                REV_INFO, REV_INFO_V2 -> parseRevInfo(listId, listData, payload, verify)
                PLAYREADY_RUNTIME, PLAYREADY_APPLICATION -> parsePlayreadyList(listId, listData, payload, verify)

                // The legacy list's signature is over a 160-bit Microsoft curve that no public
                // implementation verifies; it is carried, never vouched for.
                else -> RevocationEntry(listId, 0, listData, verified = false)
            }
        }

        /** `RLVI` / `RLV2`: a manifest of every other list's version. */
        private suspend fun parseRevInfo(
            listId: Uuid,
            listData: String,
            payload: ByteArray,
            verify: Boolean,
        ): RevocationEntry {
            val reader = ByteReader(payload)
            val magic = reader.u32("RevInfo magic")
            if (magic != MAGIC_RLVI && magic != MAGIC_RLV2) {
                throw InvalidRevocationListException("RevInfo payload has an unexpected magic $magic")
            }

            reader.u32("RevInfo length")
            reader.u8("RevInfo format version")
            reader.skip(3, "RevInfo reserved bytes")
            val sequenceNumber = reader.u32("RevInfo sequence number")
            // RLVI stores its FILETIME little-endian; RLV2 switched to big-endian.
            if (magic == MAGIC_RLVI) reader.u64Le("RevInfo issue time") else reader.u64("RevInfo issue time")

            val recordCount = reader.countOf(reader.u32("RevInfo record count") * RECORD_SIZE, "RevInfo records")
            reader.skip(recordCount, "RevInfo records")

            val signedLength = reader.position
            if (verify) verifySignature(payload, reader, signedLength, revInfoSignatureSize = true, listId = listId)

            return RevocationEntry(listId, sequenceNumber, listData, verified = verify)
        }

        /** A PlayReady runtime or application list: a set of revoked certificate digests. */
        private suspend fun parsePlayreadyList(
            listId: Uuid,
            listData: String,
            payload: ByteArray,
            verify: Boolean,
        ): RevocationEntry {
            val reader = ByteReader(payload)
            reader.bytes(16, "revocation list id")
            val version = reader.u32("revocation list version")
            val entryCount = reader.countOf(reader.u32("revocation entry count") * 32, "revocation entries")
            reader.skip(entryCount, "revocation entries")

            val signedLength = reader.position
            if (verify) verifySignature(payload, reader, signedLength, revInfoSignatureSize = false, listId = listId)

            return RevocationEntry(listId, version, listData, verified = verify)
        }

        private const val RECORD_SIZE = 24

        /**
         * Verify the ECDSA signature that follows a revocation payload's signed prefix.
         *
         * The signing key comes either from a `CHAI` chain that must itself verify as a CRL signer,
         * or from a bare 64-byte key appended in place of one.
         */
        private suspend fun verifySignature(
            payload: ByteArray,
            reader: ByteReader,
            signedLength: Int,
            revInfoSignatureSize: Boolean,
            listId: Uuid,
        ) {
            val signatureType = reader.u8("signature type")
            val signatureSize = if (revInfoSignatureSize && signatureType == 1) {
                RSA_SIGNATURE_SIZE
            } else {
                reader.u16("signature size")
            }
            val signature = reader.bytes(signatureSize, "signature")

            if (revInfoSignatureSize && signatureType == 1) reader.u32("certificate chain length")

            val trailing = reader.bytes(reader.remaining, "signing certificate")
            val signingKey = if (trailing.size == BARE_PUBLIC_KEY_SIZE) {
                trailing
            } else {
                val chain = try {
                    CertificateChain.loads(trailing)
                } catch (e: Throwable) {
                    throw InvalidRevocationListException("Revocation list $listId carries no usable signing key")
                }
                chain.verify(expectedLeafType = BCertType.CRL_SIGNER)
                chain.get(0).keyByUsage(BCertKeyUsage.SIGN_CRL)
                    ?: throw InvalidRevocationListException("Revocation list $listId signer cannot sign CRLs")
            }

            val signed = payload.copyOf(signedLength)
            if (!Ecdsa.verify(signingKey, signed, signature)) {
                throw InvalidRevocationListException("Revocation list $listId signature is not authentic")
            }
        }

        /** The fixed signature length a type-1 `RevInfo` signature declares implicitly. */
        private const val RSA_SIGNATURE_SIZE = 128

        private fun XmlReader.textOrNull(): String? = allText().trim().takeIf { it.isNotEmpty() }
    }
}
