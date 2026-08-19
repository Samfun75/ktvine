package org.samfun.ktvine

import org.samfun.ktvine.crypto.randomBytes
import org.samfun.ktvine.crypto.randomInt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CryptoTest {

    @Test
    fun `test random bytes are the requested length and not repeated`() {
        assertEquals(0, randomBytes(0).size)
        assertEquals(16, randomBytes(16).size)

        val draws = List(64) { randomBytes(16).toList() }
        assertEquals(draws.size, draws.toSet().size, "randomBytes repeated a 16-byte draw")
    }

    @Test
    fun `test key control nonce range never yields a non-positive value`() {
        // The proto field is uint32 but Wire maps it to a signed Int, so a negative draw
        // would serialise as a 10-byte varint. kotlin.random.Random.nextInt() used to make
        // one roughly half the time.
        repeat(10_000) {
            val nonce = randomInt(1, Int.MAX_VALUE)
            assertTrue(nonce > 0, "randomInt produced a non-positive nonce: $nonce")
        }
    }

    @Test
    fun `test random int covers its range`() {
        val draws = List(1_000) { randomInt(0, 4) }
        assertTrue(draws.all { it in 0..3 }, "randomInt escaped its bounds")
        assertEquals(setOf(0, 1, 2, 3), draws.toSet(), "randomInt did not cover its range")
    }
}
