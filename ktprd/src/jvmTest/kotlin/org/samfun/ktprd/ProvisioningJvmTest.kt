package org.samfun.ktprd

import kotlinx.coroutines.test.runTest
import org.samfun.ktprd.bcert.BCertKeyUsage
import org.samfun.ktprd.bcert.BCertType
import org.samfun.ktprd.bcert.CertificateChain
import org.samfun.ktprd.bcert.Provisioning
import org.samfun.ktprd.core.EccKey
import org.samfun.ktprd.core.PlayreadyDevice
import org.samfun.ktprd.utils.InvalidCertificateChainException
import org.samfun.ktprd.utils.InvalidPrdException
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Provisioning against the real group certificates on this machine.
 *
 * A leaf ktprd issues has to verify inside a chain that terminates at Microsoft's root — that is
 * the only check that says the certificate was built to the right shape rather than merely to a
 * shape ktprd's own parser accepts.
 */
class ProvisioningJvmTest {

    private val groups = listOf(
        "device/playready/Changhong-CBU-6510-PlayReady-SL3000/",
        "device/playready/LG-W23A-Playready-SL3000/",
        "device/playready/hisense_smarttv_he55a7000euwts_sl3000/",
    )

    private fun groupOrSkip(dir: String): Pair<CertificateChain, EccKey>? {
        val chainBytes = TestFixtures.orSkip(dir + "bgroupcert.dat") ?: return null
        val keyBytes = TestFixtures.orSkip(dir + "zgpriv.dat") ?: return null
        return CertificateChain.loads(chainBytes) to EccKey.loads(keyBytes)
    }

    @Test
    fun `test a device provisioned from a real group certificate verifies to the Microsoft root`() = runTest {
        var checked = 0
        for (dir in groups) {
            val (chain, groupKey) = groupOrSkip(dir) ?: continue
            checked++

            val device = Provisioning.createDevice(chain, groupKey)

            assertEquals(BCertType.DEVICE, device.groupCertificate.get(0).certType)
            assertEquals(chain.count + 1, device.groupCertificate.count)
            device.groupCertificate.verify(expectedLeafType = BCertType.DEVICE)

            val leaf = device.groupCertificate.get(0)
            assertContentEquals(device.signingKey.publicBytes, leaf.keyByUsage(BCertKeyUsage.SIGN))
            assertContentEquals(device.encryptionKey.publicBytes, leaf.keyByUsage(BCertKeyUsage.ENCRYPT_KEY))
            assertContentEquals(groupKey.publicBytes, leaf.issuerKey)
            assertEquals(chain.securityLevel, device.securityLevel)
        }
        println("provisioned $checked of ${groups.size} group certificates")
    }

    @Test
    fun `test a provisioned device round trips through a v3 prd`() = runTest {
        for (dir in groups) {
            val (chain, groupKey) = groupOrSkip(dir) ?: continue
            val device = Provisioning.createDevice(chain, groupKey)

            val reloaded = PlayreadyDevice.loads(device.dumps())
            assertContentEquals(device.dumps(), reloaded.dumps())
            assertEquals(device.name, reloaded.name)
            reloaded.groupCertificate.verify(expectedLeafType = BCertType.DEVICE)
        }
    }

    @Test
    fun `test reprovisioning replaces the leaf and its keys`() = runTest {
        for (dir in groups) {
            val (chain, groupKey) = groupOrSkip(dir) ?: continue
            val device = Provisioning.createDevice(chain, groupKey)

            val reprovisioned = Provisioning.reprovision(device)

            assertNotEquals(device.signingKey, reprovisioned.signingKey)
            assertNotEquals(device.encryptionKey, reprovisioned.encryptionKey)
            assertEquals(device.groupCertificate.count, reprovisioned.groupCertificate.count)
            reprovisioned.groupCertificate.verify(expectedLeafType = BCertType.DEVICE)
        }
    }

    @Test
    fun `test exporting a device yields the files it was built from`() = runTest {
        for (dir in groups) {
            val (chain, groupKey) = groupOrSkip(dir) ?: continue
            val device = Provisioning.createDevice(chain, groupKey)

            val (privateKey, groupCertificate) = Provisioning.exportRawKeys(device)

            assertContentEquals(groupKey.dumps(privateOnly = true), privateKey)
            assertContentEquals(chain.dumps(), groupCertificate)
        }
    }

    @Test
    fun `test a v2 device cannot be reprovisioned or exported`() = runTest {
        val (chain, groupKey) = groupOrSkip(groups[0]) ?: return@runTest
        val provisioned = Provisioning.createDevice(chain, groupKey)
        val v2 = PlayreadyDevice.loads(provisioned.dumps(version = 2))

        assertFailsWith<InvalidPrdException> { v2.dumps(version = 3) }
        assertFailsWith<InvalidPrdException> { Provisioning.reprovision(v2) }
        assertFailsWith<InvalidPrdException> { Provisioning.exportRawKeys(v2) }
    }

    @Test
    fun `test an already provisioned chain is refused`() = runTest {
        val (chain, groupKey) = groupOrSkip(groups[0]) ?: return@runTest
        val device = Provisioning.createDevice(chain, groupKey)

        assertFailsWith<InvalidCertificateChainException> {
            Provisioning.createDevice(device.groupCertificate, groupKey)
        }
    }

    @Test
    fun `test the wrong group key is refused`() = runTest {
        val (chain, _) = groupOrSkip(groups[0]) ?: return@runTest

        assertFailsWith<InvalidCertificateChainException> {
            Provisioning.createDevice(chain, EccKey.generate())
        }
    }

    @Test
    fun `test the issued leaf declares the features a PlayReady 3 client needs`() = runTest {
        val (chain, groupKey) = groupOrSkip(groups[0]) ?: return@runTest
        val device = Provisioning.createDevice(chain, groupKey)

        val features = device.groupCertificate.get(0).features()
        assertTrue(org.samfun.ktprd.bcert.BCertFeature.SECURE_CLOCK in features)
        assertTrue(org.samfun.ktprd.bcert.BCertFeature.SUPPORTS_CRLS in features)
        assertTrue(org.samfun.ktprd.bcert.BCertFeature.SUPPORTS_PLAYREADY_3_FEATURES in features)
    }
}
