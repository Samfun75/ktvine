package org.samfun.ktprd

import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.bcert.BCertKeyUsage
import org.samfun.ktprd.bcert.BCertType
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyDevice
import org.samfun.ktprd.utils.InvalidCertificateChainException
import org.samfun.ktprd.utils.InvalidPrdException
import org.samfun.ktvine.utils.ValueException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Parses and verifies the real SL3000 devices checked out on this machine.
 *
 * These are the only inputs that exercise the `bcert` and `.prd` readers against bytes Microsoft
 * actually produced, so they are what says the format work is right rather than merely
 * self-consistent. They are git-ignored, so a fresh checkout skips them out loud.
 */
class PlayreadyDeviceJvmTest {

    private val devices = listOf(
        "device/playready/Changhong-CBU-6510-PlayReady-SL3000/" +
            "sichuan_changhong_electric_co_ltd_stb_cbu-6510_sl3000.prd",
        "device/playready/Haier-ATV-hanyang-PlayReady-SL3000/" +
            "qingdao_haier_optronics_coltd_haier_atv_hanyang_sl3000_13cb583c.prd",
        "device/playready/LG-W23A-Playready-SL3000/lg_electronics_inc_lg_webos_tv_w23a_sl3000_9c34a494.prd",
        "device/playready/lg_webos_tv_sl3000/lg_electronics_inc_lg_webos_tv_msd96alvx_sl3000_30b7497d.prd",
    )

    private val groupCertificates = listOf(
        "device/playready/Changhong-CBU-6510-PlayReady-SL3000/bgroupcert.dat",
        "device/playready/Haier-ATV-hanyang-PlayReady-SL3000/bgroupcert.dat",
        "device/playready/LG-W23A-Playready-SL3000/bgroupcert.dat",
        "device/playready/MTC-ATV-PlayReady-SL3000/bgroupcert.dat",
        "device/playready/hisense_smarttv_he55a7000euwts_sl3000/bgroupcert.dat",
        "device/playready/lg_webos_tv_sl3000/bgroupcert.dat",
    )

    @Test
    fun `test every real device parses with a provisioned leaf`() {
        var checked = 0
        for (path in devices) {
            val device = PlayreadyDevice.loads(TestFixtures.orSkip(path) ?: continue)
            checked++

            assertEquals(3000, device.securityLevel, path)
            assertEquals(BCertType.DEVICE, device.groupCertificate.get(0).certType, path)
            assertTrue(device.groupCertificate.count >= 2, "$path should carry an issuer above its leaf")
            assertTrue(device.name.isNotEmpty(), path)

            // The leaf must attest to exactly the key pairs the .prd carries, or the CDM would sign
            // and decrypt with keys the server has never been told about.
            val leaf = device.groupCertificate.get(0)
            assertContentEquals(
                device.signingKey.publicBytes,
                leaf.keyByUsage(BCertKeyUsage.SIGN),
                "$path signing key",
            )
            assertContentEquals(
                device.encryptionKey.publicBytes,
                leaf.keyByUsage(BCertKeyUsage.ENCRYPT_KEY),
                "$path encryption key",
            )
        }
        println("checked $checked of ${devices.size} PlayReady devices")
    }

    @Test
    fun `test a real device round trips through its own serialization`() {
        for (path in devices) {
            val raw = TestFixtures.orSkip(path) ?: continue
            val device = PlayreadyDevice.loads(raw)
            val version = raw[3].toInt() and 0xFF

            assertContentEquals(raw, device.dumps(version), "$path did not round trip as v$version")
            assertEquals(device.name, PlayreadyDevice.loads(device.dumps(version)).name)
        }
    }

    @Test
    fun `test every real certificate chain verifies up to the Microsoft root`() = runTest {
        var checked = 0
        for (path in groupCertificates) {
            val chain = CertificateChain.loads(TestFixtures.orSkip(path) ?: continue)
            checked++

            chain.verify(expectedLeafType = BCertType.ISSUER)
            assertEquals(3000, chain.securityLevel, path)
            assertNotNull(chain.name, path)
        }
        println("verified $checked of ${groupCertificates.size} group certificate chains")
    }

    @Test
    fun `test a provisioned device chain verifies end to end`() = runTest {
        for (path in devices) {
            val device = PlayreadyDevice.loads(TestFixtures.orSkip(path) ?: continue)
            device.groupCertificate.verify(expectedLeafType = BCertType.DEVICE)
        }
    }

    @Test
    fun `test tampering with a certificate breaks its signature`() = runTest {
        val raw = TestFixtures.orSkip(groupCertificates[0]) ?: return@runTest
        val tampered = raw.copyOf()
        // Offset 50 is inside the leaf's certificate id: 20 bytes of chain header, 16 of certificate
        // header, 8 of attribute header. Flipping a length field instead would fail the parse, which
        // would prove nothing about signature verification.
        tampered[50] = (tampered[50].toInt() xor 0x01).toByte()

        val chain = CertificateChain.loads(tampered)
        assertFailsWith<InvalidCertificateChainException> { chain.verify() }
    }

    @Test
    fun `test the device group key matches the issuer above its leaf`() = runTest {
        for (path in devices) {
            val device = PlayreadyDevice.loads(TestFixtures.orSkip(path) ?: continue)
            val groupKey = device.groupKey ?: continue

            // A v3 device keeps the key that signed its leaf; that is exactly the leaf's issuer key.
            assertContentEquals(
                groupKey.publicBytes,
                device.groupCertificate.get(0).issuerKey,
                "$path group key is not the leaf's issuer",
            )
        }
    }

    @Test
    fun `test a raw group private key derives the public key its certificate lists`() {
        for (folder in groupCertificates) {
            val dir = folder.removeSuffix("bgroupcert.dat")
            val privateKey = TestFixtures.orSkip(dir + "zgpriv.dat") ?: continue
            val chain = CertificateChain.loads(TestFixtures.read(folder))

            val key = EccKey.loads(privateKey)
            assertTrue(
                chain.get(0).containsPublicKey(key.publicBytes),
                "$dir zgpriv.dat does not match bgroupcert.dat",
            )
        }
    }

    @Test
    fun `test a truncated device is rejected`() {
        val raw = TestFixtures.orSkip(devices[0]) ?: return
        assertFailsWith<ValueException> { PlayreadyDevice.loads(raw.copyOf(raw.size / 2)) }
    }

    @Test
    fun `test data without the PRD magic is rejected`() {
        assertFailsWith<InvalidPrdException> { PlayreadyDevice.loads(byteArrayOf(1, 2, 3, 4, 5)) }
    }
}
