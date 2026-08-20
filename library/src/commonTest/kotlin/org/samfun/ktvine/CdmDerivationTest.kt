package org.samfun.ktvine

import kotlinx.coroutines.test.runTest
import okio.ByteString.Companion.decodeHex
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Golden vectors for the NIST SP 800-108 counter-mode ladder that turns a session key into
 * the content-encryption and MAC keys.
 *
 * The expected values were produced by an independent implementation (pyca/cryptography's
 * CMAC, driven the way pywidevine's `derive_context` / `derive_keys` do it), not by ktvine.
 * Get this wrong and every key a license delivers is wrong, so it must not be checked
 * against ktvine's own output.
 */
class CdmDerivationTest {

    private val licenseRequest = ByteArray(64) { it.toByte() }
    private val sessionKey = "000102030405060708090a0b0c0d0e0f".decodeHex().toByteArray()

    private fun cdm() = Cdm(DeviceTypes.ANDROID, ClientIdentification(), ByteArray(0))

    @Test
    fun `test derived context matches the independent implementation`() {
        val (encContext, macContext) = cdm().deriveContext(licenseRequest)

        assertEquals(
            "454e4352595054494f4e00" +
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                "00000080",
            encContext.toHexString(),
            "ENCRYPTION label, NUL, the request, then the key size in bits big-endian",
        )
        assertEquals(
            "41555448454e5449434154494f4e00" +
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" +
                "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f" +
                "00000200",
            macContext.toHexString(),
            "AUTHENTICATION context must ask for 512 bits, not 128",
        )
    }

    @Test
    fun `test derived keys match the independent implementation`() = runTest {
        val cdm = cdm()
        val (encContext, macContext) = cdm.deriveContext(licenseRequest)
        val (encKey, macKeyServer, macKeyClient) = cdm.deriveKeys(encContext, macContext, sessionKey)

        assertEquals("cf6900a60699fbed5c49f83abfb9dd62", encKey.toHexString())
        assertEquals(
            "cae239b612323bd4362f61f390abbc42d39de3c9abacc9fce2b3eb8e8e1db621",
            macKeyServer.toHexString(),
            "server MAC key is counters 1 and 2 concatenated",
        )
        assertEquals(
            "698ce6b6feb977a521ba0acee50e5143f0baef7f14f6760e7da055bb0b6437b3",
            macKeyClient.toHexString(),
            "client MAC key is counters 3 and 4 concatenated",
        )
    }

    @Test
    fun `test the three derived keys are distinct`() = runTest {
        val cdm = cdm()
        val (encContext, macContext) = cdm.deriveContext(licenseRequest)
        val (encKey, macKeyServer, macKeyClient) = cdm.deriveKeys(encContext, macContext, sessionKey)

        assertEquals(16, encKey.size)
        assertEquals(32, macKeyServer.size)
        assertEquals(32, macKeyClient.size)
        assertEquals(
            3,
            setOf(encKey.toHexString(), macKeyServer.toHexString(), macKeyClient.toHexString()).size,
        )
    }
}
