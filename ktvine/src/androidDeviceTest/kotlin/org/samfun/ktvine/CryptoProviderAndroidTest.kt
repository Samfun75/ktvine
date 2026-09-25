package org.samfun.ktvine

import dev.whyoleg.cryptography.CryptographyProvider
import java.security.Security
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class CryptoProviderAndroidTest {

    @Test
    fun `test the default provider is the JDK one over bundled BouncyCastle`() {
        assertEquals("JDK (BC)", CryptographyProvider.Default.name)
        // Android's own "BC" is a stripped copy under com.android.org, so the name alone proves nothing.
        assertNotNull(Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider"))
    }

    @Test
    fun `test the platform JCA still has no RSASSA-PSS`() {
        assertNull(
            Security.getProviders("Signature.RSASSA-PSS"),
            "Android now ships RSASSA-PSS itself, so provider-jdk-bc may no longer be needed",
        )
    }
}
