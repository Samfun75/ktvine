package org.samfun.ktvine

import dev.whyoleg.cryptography.CryptographyProvider
import kotlin.test.Test
import kotlin.test.assertTrue

class CryptoProviderLinuxTest {

    @Test
    fun `test the default provider is OpenSSL 3`() {
        val name = CryptographyProvider.Default.name
        assertTrue(name.startsWith("OpenSSL3 (3."), "unexpected provider: $name")
    }
}
