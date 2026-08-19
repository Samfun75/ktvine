package org.samfun.ktvine

import kotlinx.coroutines.runBlocking
import okio.ByteString.Companion.decodeHex
import org.samfun.ktvine.crypto.aesCmac
import org.samfun.ktvine.crypto.hmacSha256
import org.samfun.ktvine.utils.toHexString
import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Known-answer vectors for the hand-rolled AES-CMAC.
 *
 * ktvine implements CMAC itself because no cryptography-kotlin provider offers it on every
 * target, so these vectors are the only thing standing between a subtle bug here and every
 * derived key being wrong.
 */
class AesCmacJvmTest {

    private val key = "2b7e151628aed2a6abf7158809cf4f3c".decodeHex().toByteArray()
    private val message =
        ("6bc1bee22e409f96e93d7e117393172a" +
            "ae2d8a571e03ac9c9eb76fac45af8e51" +
            "30c81c46a35ce411e5fbc1191a0a52ef" +
            "f69f2445df4f9b17ad2b417be66c3710").decodeHex().toByteArray()

    private fun cmacHex(length: Int): String = runBlocking {
        aesCmac(key, message.copyOfRange(0, length)).toHexString()
    }

    @Test
    fun `test RFC 4493 example 1 empty message`() {
        assertEquals("bb1d6929e95937287fa37d129b756746", cmacHex(0))
    }

    @Test
    fun `test RFC 4493 example 2 one block`() {
        assertEquals("070a16b46b4d4144f79bdd9dd04a287c", cmacHex(16))
    }

    @Test
    fun `test RFC 4493 example 3 partial block`() {
        assertEquals("dfa66747de9ae63030ca32611497c827", cmacHex(40))
    }

    @Test
    fun `test RFC 4493 example 4 four blocks`() {
        assertEquals("51f0bebf7e3b9d92fc49741779363cfe", cmacHex(64))
    }

    @Test
    fun `test RFC 4231 hmac sha256 case 1`() {
        runBlocking {
            val mac = hmacSha256(
                ByteArray(20) { 0x0b },
                "Hi There".encodeToByteArray()
            )
            assertEquals(
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
                mac.toHexString()
            )
        }
    }
}
