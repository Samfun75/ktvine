package org.samfun.ktvine

import co.touchlab.kermit.LogWriter
import co.touchlab.kermit.Logger
import co.touchlab.kermit.Severity
import co.touchlab.kermit.loggerConfigInit
import org.samfun.ktvine.core.PSSH
import org.samfun.ktvine.utils.KtvineLog
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.uuid.Uuid

class KtvineLogTest {

    private class Recorder : LogWriter() {
        val lines = mutableListOf<Pair<Severity, String>>()
        override fun log(severity: Severity, message: String, tag: String, throwable: Throwable?) {
            lines += severity to message
        }
    }

    @AfterTest
    fun restoreDefaults() = KtvineLog.reset()

    private fun capture(minSeverity: Severity): Recorder {
        val recorder = Recorder()
        KtvineLog.setLogger(
            Logger(loggerConfigInit(recorder, minSeverity = minSeverity), tag = "ktvine")
        )
        return recorder
    }

    /** Parsing a bare CENC header walks the box parser and hits the verbose path. */
    private fun parseSomething() {
        PSSH.new(
            systemId = Uuid.parse("edef8ba9-79d6-4ace-a3c8-27dcd51d21ed"),
            keyIds = listOf(Uuid.parse("11111111-2222-3333-4444-555555555555")),
            version = 1
        ).export().let { PSSH(it) }
    }

    @Test
    fun `test the library is quiet at the default severity`() {
        val recorder = capture(Severity.Warn)
        parseSomething()
        assertEquals(
            emptyList(),
            recorder.lines,
            "PSSH parsing should not log below Warn by default"
        )
    }

    @Test
    fun `test verbose reveals the parse trace`() {
        val recorder = capture(Severity.Verbose)
        parseSomething()
        assertTrue(recorder.lines.isNotEmpty(), "verbose should surface the parse trace")
        assertTrue(
            recorder.lines.all { it.first >= Severity.Verbose },
            "unexpected severity in ${recorder.lines}"
        )
    }

    @Test
    fun `test the init data hex dump is verbose only`() {
        val atDebug = capture(Severity.Debug)
        parseSomething()
        assertTrue(
            atDebug.lines.none { it.second.contains("ISOBMFF box sequence") },
            "the hex dump must not appear at Debug: ${atDebug.lines}"
        )

        val atVerbose = capture(Severity.Verbose)
        parseSomething()
        assertTrue(
            atVerbose.lines.any { it.second.contains("ISOBMFF box sequence") },
            "the hex dump should appear at Verbose: ${atVerbose.lines}"
        )
    }
}
