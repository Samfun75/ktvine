package org.samfun.ktvine

import kotlinx.coroutines.test.runTest
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.utils.InvalidSessionException
import org.samfun.ktvine.utils.TooManySessionsException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CdmSessionTest {

    // Session lifecycle needs neither a real client id nor a real key.
    private fun cdm() = Cdm(DeviceTypes.ANDROID, ClientIdentification(), ByteArray(0))

    @Test
    fun `test open refuses more than the documented session limit`() = runTest {
        val cdm = cdm()
        val ids = List(Cdm.MAX_NUM_OF_SESSIONS) { cdm.open() }

        assertEquals(Cdm.MAX_NUM_OF_SESSIONS, ids.toSet().size, "session ids must be unique")
        // pywidevine's `> 16` lets a 17th through; ktvine stops at 16.
        assertFailsWith<TooManySessionsException> { cdm.open() }

        cdm.close(ids.first())
        cdm.open()
        assertFailsWith<TooManySessionsException> { cdm.open() }
    }

    @Test
    fun `test close rejects an unknown session id`() = runTest {
        val cdm = cdm()
        val id = cdm.open()
        cdm.close(id)
        assertFailsWith<InvalidSessionException> { cdm.close(id) }
    }

    @Test
    fun `test getKeys rejects an unknown session id`() = runTest {
        assertFailsWith<InvalidSessionException> { cdm().getKeys(cdm().open()) }
    }
}
