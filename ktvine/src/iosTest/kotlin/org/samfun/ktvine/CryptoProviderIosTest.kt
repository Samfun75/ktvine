package org.samfun.ktvine

import dev.whyoleg.cryptography.CryptographyAlgorithmId
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.providers.apple.Apple
import dev.whyoleg.cryptography.providers.cryptokit.CryptoKit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

@OptIn(DelicateCryptographyApi::class)
class CryptoProviderIosTest {

    private val cryptoKitGaps: List<CryptographyAlgorithmId<*>> = listOf(RSA.PSS, RSA.OAEP, AES.CBC, AES.ECB)

    @Test
    fun `test the default provider tries CryptoKit then Apple`() {
        assertEquals("Composite(CryptoKit,Apple)", CryptographyProvider.Default.name)
    }

    @Test
    fun `test every algorithm CryptoKit lacks is served by the Apple provider`() {
        for (id in cryptoKitGaps) {
            assertNull(CryptographyProvider.CryptoKit.getOrNull(id), "CryptoKit now serves ${id.name}")
            assertNotNull(CryptographyProvider.Apple.getOrNull(id), "the Apple provider no longer serves ${id.name}")
        }
    }
}
