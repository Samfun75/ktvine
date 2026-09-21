package org.samfun.ktprd

import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.cdm.PlayreadyCdm
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktprd.revocation.InMemoryRevocationStore
import org.samfun.ktprd.revocation.RevocationList
import org.samfun.ktprd.utils.ByteWriter
import org.samfun.ktprd.utils.InvalidRevocationListException
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.toLittleEndianByteArray
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * Revocation data as it actually moves: parsed out of a `RevInfo`, merged by version, kept in a
 * store, and advertised back in the next challenge.
 *
 * Signatures are not exercised here — a payload signed by Microsoft's CRL signer cannot be
 * manufactured — so everything parses with `verify = false`, which is also the path the CDM takes
 * when reading its own stored document back.
 */
class RevocationListTest {

    private val kid = Uuid.parse("11223344-5566-7788-99aa-bbccddeeff00")

    /** An `RLV2` manifest declaring [sequenceNumber], with no records and no signature. */
    private fun revInfoPayload(sequenceNumber: Int): ByteArray = ByteWriter()
        .u32(0x524C5632)
        .u32(0)
        .u8(1)
        .bytes(ByteArray(3))
        .u32(sequenceNumber)
        .bytes(ByteArray(8))
        .u32(0)
        .toByteArray()

    /** A PlayReady runtime or application list at [version], with no entries and no signature. */
    private fun playreadyListPayload(listId: Uuid, version: Int): ByteArray = ByteWriter()
        .bytes(listId.toLittleEndianByteArray())
        .u32(version)
        .u32(0)
        .toByteArray()

    private fun revInfo(vararg lists: Pair<Uuid, ByteArray>): String = buildString {
        append("<RevInfo>")
        for ((listId, payload) in lists) {
            append("<Revocation>")
            append("<ListID>").append(Base64.encode(listId.toLittleEndianByteArray())).append("</ListID>")
            append("<ListData>").append(Base64.encode(payload)).append("</ListData>")
            append("</Revocation>")
        }
        append("</RevInfo>")
    }

    @Test
    fun `test a RevInfo manifest yields the sequence number it declares`() = runTest {
        val document = revInfo(RevocationList.REV_INFO_V2 to revInfoPayload(sequenceNumber = 42))

        val parsed = RevocationList.parse(document, verify = false)

        assertEquals(42L, parsed.versionOf(RevocationList.REV_INFO_V2))
        assertEquals(0L, parsed.versionOf(RevocationList.PLAYREADY_RUNTIME), "an absent list is version 0")
    }

    @Test
    fun `test a runtime list yields its own version`() = runTest {
        val document = revInfo(
            RevocationList.PLAYREADY_RUNTIME to playreadyListPayload(RevocationList.PLAYREADY_RUNTIME, 7),
            RevocationList.PLAYREADY_APPLICATION to playreadyListPayload(RevocationList.PLAYREADY_APPLICATION, 9),
        )

        val parsed = RevocationList.parse(document, verify = false)

        assertEquals(7L, parsed.versionOf(RevocationList.PLAYREADY_RUNTIME))
        assertEquals(9L, parsed.versionOf(RevocationList.PLAYREADY_APPLICATION))
    }

    @Test
    fun `test the legacy network list is carried but never vouched for`() = runTest {
        val document = revInfo(RevocationList.WMDRM_NETWORK to byteArrayOf(1, 2, 3, 4))

        val entry = RevocationList.parse(document, verify = false).entry(RevocationList.WMDRM_NETWORK)

        assertNotNull(entry)
        assertTrue(!entry.verified, "the 160-bit curve this list is signed over cannot be verified")
    }

    @Test
    fun `test merging keeps the newer version of each list`() = runTest {
        val current = revInfo(
            RevocationList.REV_INFO_V2 to revInfoPayload(sequenceNumber = 5),
            RevocationList.PLAYREADY_RUNTIME to playreadyListPayload(RevocationList.PLAYREADY_RUNTIME, 3),
        )
        val incoming = revInfo(
            RevocationList.REV_INFO_V2 to revInfoPayload(sequenceNumber = 4),
            RevocationList.PLAYREADY_RUNTIME to playreadyListPayload(RevocationList.PLAYREADY_RUNTIME, 8),
            RevocationList.PLAYREADY_APPLICATION to playreadyListPayload(RevocationList.PLAYREADY_APPLICATION, 1),
        )

        val merged = RevocationList.parse(RevocationList.merge(current, incoming), verify = false)

        assertEquals(5L, merged.versionOf(RevocationList.REV_INFO_V2), "an older incoming list must not win")
        assertEquals(8L, merged.versionOf(RevocationList.PLAYREADY_RUNTIME))
        assertEquals(1L, merged.versionOf(RevocationList.PLAYREADY_APPLICATION), "a new list must be added")
    }

    @Test
    fun `test a document that is not a RevInfo is refused`() = runTest {
        assertFailsWith<InvalidRevocationListException> {
            RevocationList.parse("<NotRevInfo></NotRevInfo>", verify = false)
        }
        assertFailsWith<InvalidRevocationListException> {
            RevocationList.parse("<RevInfo><Revocation><ListID>not base64!</ListID></Revocation></RevInfo>", false)
        }
    }

    @Test
    fun `test reading a stored version tolerates a document it cannot parse`() = runTest {
        assertEquals(0L, RevocationList.versionOf("nonsense".encodeToByteArray(), RevocationList.REV_INFO_V2))
    }

    @Test
    fun `test a byte order mark does not stop a document parsing`() = runTest {
        val document = revInfo(RevocationList.REV_INFO_V2 to revInfoPayload(sequenceNumber = 11))
        val withBom = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()) + document.encodeToByteArray()

        assertEquals(11L, RevocationList.versionOf(withBom, RevocationList.REV_INFO_V2))
    }

    @Test
    fun `test a challenge advertises the versions the store already holds`() = runTest {
        val store = InMemoryRevocationStore()
        store.write(
            RevocationList.CURRENT_LIST_FILE_NAME,
            revInfo(
                RevocationList.PLAYREADY_RUNTIME to playreadyListPayload(RevocationList.PLAYREADY_RUNTIME, 21),
            ).encodeToByteArray(),
        )

        val challenge = cdmWith(store).let { cdm ->
            cdm.getLicenseChallenge(cdm.open(), header(), listOf(RevocationList.PLAYREADY_RUNTIME))
        }

        assertTrue(challenge.contains("<Version>21</Version>"), "the stored version must be advertised")
    }

    @Test
    fun `test revocation data a license came with is kept for the next challenge`() = runTest {
        val store = InMemoryRevocationStore()
        val server = TestLicenseServer()
        val cdm = cdmWith(store, server)

        val sessionId = cdm.open()
        val response = server.issueLicense(
            cdm.getLicenseChallenge(sessionId, header()),
            kid,
            revocationInfo = revInfo(
                RevocationList.PLAYREADY_RUNTIME to playreadyListPayload(RevocationList.PLAYREADY_RUNTIME, 30),
            ),
        )
        cdm.parseLicense(sessionId, response)

        val stored = store.read(RevocationList.CURRENT_LIST_FILE_NAME)
        assertNotNull(stored, "the server sent revocation data and nothing kept it")
        assertEquals(30L, RevocationList.versionOf(stored, RevocationList.PLAYREADY_RUNTIME))

        val next = cdm.getLicenseChallenge(cdm.open(), header(), listOf(RevocationList.PLAYREADY_RUNTIME))
        assertTrue(next.contains("<Version>30</Version>"))
    }

    private fun header(): WrmHeader = WrmHeader.parse(PlayreadyHeader.build(keyIds = listOf(kid), algid = "AESCTR"))

    private suspend fun cdmWith(
        store: InMemoryRevocationStore,
        server: TestLicenseServer = TestLicenseServer(),
    ): PlayreadyCdm {
        val device = TestDevice.create()
        return PlayreadyCdm(
            securityLevel = device.securityLevel,
            certificateChain = device.groupCertificate,
            encryptionKey = device.encryptionKey,
            signingKey = device.signingKey,
            revocationStore = store,
            wmrmPublicPoint = server.publicPoint,
        )
    }
}
