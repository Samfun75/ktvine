package org.samfun.ktvine

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.samfun.ktvine.cdm.Cdm
import org.samfun.ktvine.core.DeviceTypes
import org.samfun.ktvine.proto.ClientIdentification
import org.samfun.ktvine.utils.TooManySessionsException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * Exercises [Cdm] from several threads at once. `runTest` runs everything on one thread, so
 * these live here on a real multi-threaded dispatcher.
 */
class CdmConcurrencyJvmTest {

    private fun cdm() = Cdm(DeviceTypes.ANDROID, ClientIdentification(), ByteArray(0))

    @Test
    fun `test concurrent opens hand out distinct session ids`() {
        runBlocking {
            val cdm = cdm()
            val ids = withContext(Dispatchers.Default) {
                coroutineScope {
                    List(Cdm.MAX_NUM_OF_SESSIONS) { async { cdm.open() } }.awaitAll()
                }
            }

            assertEquals(
                Cdm.MAX_NUM_OF_SESSIONS,
                ids.toSet().size,
                "concurrent open() produced duplicate session ids",
            )
            assertFailsWith<TooManySessionsException> { cdm.open() }
        }
    }

    @Test
    fun `test concurrent open and close churn leaves the session map consistent`() {
        runBlocking {
            val cdm = cdm()
            withContext(Dispatchers.Default) {
                coroutineScope {
                    repeat(8) {
                        launch {
                            repeat(200) { cdm.close(cdm.open()) }
                        }
                    }
                }
            }

            // Every session was closed, so the full quota must be available again.
            val ids = List(Cdm.MAX_NUM_OF_SESSIONS) { cdm.open() }
            assertEquals(Cdm.MAX_NUM_OF_SESSIONS, ids.toSet().size)
            assertFailsWith<TooManySessionsException> { cdm.open() }
        }
    }
}
