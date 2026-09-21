package org.samfun.ktprd

import kotlinx.coroutines.test.runTest
import okio.ByteString
import org.samfun.ktprd.cdm.PlayreadyCdm
import org.samfun.ktprd.core.PlayreadyCipherType
import org.samfun.ktprd.core.PlayreadyKeyType
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktprd.crypto.aesEcbEncrypt
import org.samfun.ktprd.revocation.RevocationList
import org.samfun.ktprd.utils.InvalidLicenseResponseException
import org.samfun.ktprd.utils.PlayreadyServerException
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.InvalidSessionException
import org.samfun.ktvine.utils.TooManySessionsException
import org.samfun.ktvine.utils.toHexString
import org.samfun.ktvine.utils.toLittleEndianByteArray
import kotlin.io.encoding.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

/**
 * A complete license exchange with no network and no real device.
 *
 * This runs on every target, so the curve, the AES-CBC session key, the XMR parse and the whole
 * XML layer are exercised on iOS and Linux rather than only on the JVM. The server side re-derives
 * the challenge's own digest and signature from the bytes it received, so a mismatch between what
 * the builder hashes and what it sends fails here rather than at a real license server.
 */
class CdmOfflineExchangeTest {

    private val kid = Uuid.parse("11223344-5566-7788-99aa-bbccddeeff00")

    private fun header(): WrmHeader = WrmHeader.parse(
        PlayreadyHeader.build(keyIds = listOf(kid), algid = "AESCTR", laUrl = "https://ls.example.com/rights"),
    )

    private suspend fun cdmFor(server: TestLicenseServer): PlayreadyCdm {
        val device = TestDevice.create()
        return PlayreadyCdm(
            securityLevel = device.securityLevel,
            certificateChain = device.groupCertificate,
            encryptionKey = device.encryptionKey,
            signingKey = device.signingKey,
            wmrmPublicPoint = server.publicPoint,
        )
    }

    @Test
    fun `test a full exchange yields the content key the server issued`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)

        val sessionId = cdm.open()
        val challenge = cdm.getLicenseChallenge(sessionId, header())
        val response = server.issueLicense(challenge, kid)

        cdm.parseLicense(sessionId, response)
        val keys = cdm.getKeys(sessionId)

        assertEquals(1, keys.size)
        assertEquals(kid, keys[0].kid)
        assertEquals(PlayreadyKeyType.AES_128_CTR, keys[0].keyType)
        assertEquals(PlayreadyCipherType.ECC_256, keys[0].cipherType)
        assertEquals(server.issuedKey.toHexString(), keys[0].key.toHexString())

        cdm.close(sessionId)
    }

    @Test
    fun `test a signed license response verifies before its keys are trusted`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)

        val sessionId = cdm.open()
        val challenge = cdm.getLicenseChallenge(sessionId, header())
        val response = server.issueLicense(challenge, kid, sign = true)

        cdm.parseLicense(sessionId, response)
        assertEquals(server.issuedKey.toHexString(), cdm.getKeys(sessionId).single().key.toHexString())
    }

    @Test
    fun `test a tampered signed response is refused`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)

        val sessionId = cdm.open()
        val challenge = cdm.getLicenseChallenge(sessionId, header())
        val response = server.issueLicense(challenge, kid, sign = true)

        // Change the response id, which the digest covers but nothing else reads.
        val tampered = response.replace("<ResponseID>1</ResponseID>", "<ResponseID>2</ResponseID>")

        assertFailsWith<InvalidLicenseResponseException> { cdm.parseLicense(sessionId, tampered) }
    }

    @Test
    fun `test the challenge declares the protocol version its header calls for`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)
        val sessionId = cdm.open()

        val challenge = cdm.getLicenseChallenge(sessionId, header())

        // PlayreadyHeader.build emits 4.3.0.0, which is protocol version 5.
        assertEquals("4.3.0.0", header().version)
        assertEquals(5, header().protocolVersion)
        assertTrue(challenge.contains("<Version>5</Version>"))
    }

    @Test
    fun `test the header is embedded verbatim rather than re-serialized`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)
        val sessionId = cdm.open()

        val wrmHeader = header()
        val challenge = cdm.getLicenseChallenge(sessionId, wrmHeader)

        assertTrue(
            challenge.contains("<ContentHeader>${wrmHeader.xml}</ContentHeader>"),
            "the ContentHeader must carry the document exactly as given",
        )
    }

    @Test
    fun `test advertised revocation lists appear in the challenge`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)
        val sessionId = cdm.open()

        val challenge = cdm.getLicenseChallenge(sessionId, header(), RevocationList.SUPPORTED_LIST_IDS)

        assertTrue(challenge.contains("<RevocationLists>"))
        // Nothing is stored, so every list is advertised at version 0.
        assertEquals(
            RevocationList.SUPPORTED_LIST_IDS.size,
            Regex("<Version>0</Version>").findAll(challenge).count(),
        )
    }

    @Test
    fun `test a server fault surfaces as a named DRM error`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)
        val sessionId = cdm.open()
        cdm.getLicenseChallenge(sessionId, header())

        val fault = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" +
            "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\"><soap:Body><soap:Fault>" +
            "<faultstring>the device is not authorised</faultstring>" +
            "<detail><Exception><StatusCode>0x8004C006</StatusCode></Exception></detail>" +
            "</soap:Fault></soap:Body></soap:Envelope>"

        val error = assertFailsWith<PlayreadyServerException> { cdm.parseLicense(sessionId, fault) }
        assertTrue(error.message!!.contains("the device is not authorised"))
        assertTrue(error.message!!.contains("DRM_E_INVALID_LICENSE"), "the code must be named, not just echoed")
        assertEquals(0x8004C006.toInt(), error.statusCode)
    }

    @Test
    fun `test parsing a license without a challenge is refused`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)
        val sessionId = cdm.open()

        assertFailsWith<InvalidSessionException> { cdm.parseLicense(sessionId, "<soap:Envelope/>") }
    }

    @Test
    fun `test an unknown session is refused by every call`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)
        val bogus = ByteString.of(*ByteArray(16))

        assertFailsWith<InvalidSessionException> { cdm.getKeys(bogus) }
        assertFailsWith<InvalidSessionException> { cdm.close(bogus) }
        assertFailsWith<InvalidSessionException> { cdm.getLicenseChallenge(bogus, header()) }
    }

    @Test
    fun `test the session cap is the number of sessions and not one more`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)

        val opened = (1..PlayreadyCdm.MAX_NUM_OF_SESSIONS).map { cdm.open() }
        assertFailsWith<TooManySessionsException> { cdm.open() }

        cdm.close(opened.first())
        cdm.open()
    }

    @Test
    fun `test each session gets its own identifier and key set`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)

        val first = cdm.open()
        val second = cdm.open()
        assertTrue(first != second)

        val challenge = cdm.getLicenseChallenge(first, header())
        cdm.parseLicense(first, server.issueLicense(challenge, kid))

        assertEquals(1, cdm.getKeys(first).size)
        assertEquals(0, cdm.getKeys(second).size, "a session must not see another session's keys")
    }

    @Test
    fun `test a content key checks out against the header checksum`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)
        val sessionId = cdm.open()

        val response = server.issueLicense(cdm.getLicenseChallenge(sessionId, header()), kid)
        cdm.parseLicense(sessionId, response)
        val key = cdm.getKeys(sessionId).single()

        // Build a header advertising the checksum this key actually produces, then confirm the
        // check accepts it and rejects a key that is one bit different.
        val checksummed = WrmHeader.parse(headerWithChecksum(checksumFor(key.key)))
        assertTrue(checksummed.verifyChecksum(kid, key.key))

        val wrongKey = key.key.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() }
        assertTrue(!checksummed.verifyChecksum(kid, wrongKey))
    }

    private suspend fun checksumFor(contentKey: ByteArray): ByteArray =
        aesEcbEncrypt(contentKey, kid.toLittleEndianByteArray()).copyOf(8)

    private fun headerWithChecksum(checksum: ByteArray): String =
        "<WRMHEADER xmlns=\"${PlayreadyHeader.NAMESPACE}\" version=\"4.3.0.0\"><DATA><PROTECTINFO><KIDS>" +
            "<KID ALGID=\"AESCTR\" CHECKSUM=\"${Base64.encode(checksum)}\" " +
            "VALUE=\"${Base64.encode(kid.toLittleEndianByteArray())}\"></KID>" +
            "</KIDS></PROTECTINFO></DATA></WRMHEADER>"

    @Test
    fun `test the issued key id round trips as a little endian GUID`() = runTest {
        val server = TestLicenseServer()
        val cdm = cdmFor(server)
        val sessionId = cdm.open()

        cdm.parseLicense(sessionId, server.issueLicense(cdm.getLicenseChallenge(sessionId, header()), kid))

        assertContentEquals(
            kid.toLittleEndianByteArray(),
            cdm.getKeys(sessionId).single().kid.toLittleEndianByteArray(),
        )
    }
}
