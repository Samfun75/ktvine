package org.samfun.ktvine

import dev.whyoleg.cryptography.CryptographyProvider
import java.security.Signature
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CryptoProviderJvmTest {

    @Test
    fun `test the default provider is the plain JDK one`() {
        assertEquals("JDK", CryptographyProvider.Default.name)
    }

    @Test
    fun `test BouncyCastle stays off the JVM classpath`() {
        assertFailsWith<ClassNotFoundException>("provider-jdk-bc belongs in androidMain only") {
            Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider")
        }
    }

    @Test
    fun `test RSASSA-PSS comes from the JDK itself`() {
        assertEquals("SunRsaSign", Signature.getInstance("RSASSA-PSS").provider.name)
    }
}
