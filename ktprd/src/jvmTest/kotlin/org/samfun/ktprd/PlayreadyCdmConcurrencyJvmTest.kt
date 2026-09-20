@file:OptIn(ExperimentalUuidApi::class)

package org.samfun.ktprd

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.samfun.ktprd.cdm.PlayreadyCdm
import org.samfun.ktprd.core.WrmHeader
import org.samfun.ktvine.core.PlayreadyHeader
import org.samfun.ktvine.utils.TooManySessionsException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

/**
 * Exercises [PlayreadyCdm] from several threads at once, as `CdmConcurrencyJvmTest` does for
 * Widevine. `runTest` runs everything on one thread, so these need a real dispatcher and live
 * here rather than in `commonTest`.
 *
 * Drop either the session-map lock or the per-session lock and these fail.
 */
class PlayreadyCdmConcurrencyJvmTest {

    private suspend fun cdm() = PlayreadyCdm.fromDevice(TestDevice.create())

    @Test
    fun `test concurrent opens hand out distinct session ids`() {
        runBlocking {
            val cdm = cdm()
            val ids = withContext(Dispatchers.Default) {
                coroutineScope {
                    List(PlayreadyCdm.MAX_NUM_OF_SESSIONS) { async { cdm.open() } }.awaitAll()
                }
            }

            assertEquals(
                PlayreadyCdm.MAX_NUM_OF_SESSIONS,
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

            val ids = List(PlayreadyCdm.MAX_NUM_OF_SESSIONS) { cdm.open() }
            assertEquals(PlayreadyCdm.MAX_NUM_OF_SESSIONS, ids.toSet().size)
            assertFailsWith<TooManySessionsException> { cdm.open() }
        }
    }

    @Test
    fun `test concurrent challenges on one session do not interleave their state`() {
        runBlocking {
            val cdm = cdm()
            val header = WrmHeader.parse(PlayreadyHeader.build(keyIds = listOf(Uuid.random()), algid = "AESCTR"))
            val sessionId = cdm.open()

            val challenges = withContext(Dispatchers.Default) {
                coroutineScope {
                    List(32) { async { cdm.getLicenseChallenge(sessionId, header) } }.awaitAll()
                }
            }

            // Only the session's XML key and IV vary here, so a torn read of it differs.
            val clientData = challenges.map {
                it.substringAfterLast("<CipherValue>").substringBefore("</CipherValue>")
            }
            assertEquals(1, clientData.toSet().size, "a session's XML key changed under concurrent challenges")
        }
    }
}
