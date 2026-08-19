package org.samfun.ktvine

import org.samfun.ktvine.core.Key
import org.samfun.ktvine.proto.License
import kotlin.uuid.Uuid
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class KeyTest {

    private val kid: Uuid = Uuid.parse("00000000-0000-0000-0000-000000000001")

    private fun key(
        type: License.KeyContainer.KeyType = License.KeyContainer.KeyType.CONTENT,
        bytes: ByteArray = byteArrayOf(1, 2, 3, 4)
    ) = Key(type, kid, bytes)

    @Test
    fun `test keys compare by key content not identity`() {
        // A data class would compare the ByteArray by reference and never match here.
        assertEquals(key(), key(bytes = byteArrayOf(1, 2, 3, 4)))
        assertEquals(key().hashCode(), key(bytes = byteArrayOf(1, 2, 3, 4)).hashCode())

        assertNotEquals(key(), key(bytes = byteArrayOf(9, 9, 9, 9)))
        assertNotEquals(key(), key(type = License.KeyContainer.KeyType.SIGNING))
        assertNotEquals(key(), Key(License.KeyContainer.KeyType.CONTENT, Uuid.fromLongs(0, 2), byteArrayOf(1, 2, 3, 4)))
    }

    @Test
    fun `test keys are usable in sets`() {
        val set = setOf(key(), key(bytes = byteArrayOf(1, 2, 3, 4)))
        assertEquals(1, set.size, "equal keys must collapse in a Set")
    }

    @Test
    fun `test key type is the protobuf enum`() {
        val k = key(type = License.KeyContainer.KeyType.OPERATOR_SESSION)
        assertEquals(License.KeyContainer.KeyType.OPERATOR_SESSION, k.type)
        // Filtering used to compare against `type.name`, which quietly matched nothing
        // when the two spellings drifted.
        assertTrue(k.toString().contains("OPERATOR_SESSION"))
    }
}
