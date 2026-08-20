package org.samfun.ktvine.utils

import co.touchlab.kermit.Logger
import co.touchlab.kermit.Severity
import co.touchlab.kermit.loggerConfigInit
import co.touchlab.kermit.platformLogWriter

/**
 * Every log line this library emits goes through here.
 *
 * The library is quiet by default: only [Severity.Warn] and above reach the platform log,
 * so a host application's log is not filled with per-PSSH parse chatter. Raise the level
 * with [setMinSeverity] when debugging a license exchange, or replace the sink entirely
 * with [setLogger] to route into an existing logging setup.
 */
public object KtvineLog {

    internal const val TAG: String = "ktvine"

    private var delegate: Logger = loggerFor(Severity.Warn)

    private fun loggerFor(minSeverity: Severity): Logger =
        Logger(
            config = loggerConfigInit(platformLogWriter(), minSeverity = minSeverity),
            tag = TAG
        )

    /**
     * Raise or lower how much this library logs. Defaults to [Severity.Warn].
     *
     * PSSH and license internals log at [Severity.Verbose] and [Severity.Debug]. Note that
     * verbose includes a hex dump of the init data being parsed, which callers may consider
     * sensitive.
     */
    public fun setMinSeverity(severity: Severity) {
        delegate = loggerFor(severity)
    }

    /** Route this library's logging into an existing Kermit [Logger]. */
    public fun setLogger(logger: Logger) {
        delegate = logger
    }

    /** Restore the default sink and severity. */
    public fun reset() {
        delegate = loggerFor(Severity.Warn)
    }

    // Not inline: forwarding an inline lambda parameter on to Kermit's own inline methods
    // is not allowed, and the allocation is irrelevant next to a license exchange.
    internal fun v(message: () -> String) = delegate.v(null, TAG, message)

    internal fun d(message: () -> String) = delegate.d(null, TAG, message)

    internal fun w(message: () -> String) = delegate.w(null, TAG, message)

    internal fun e(throwable: Throwable? = null, message: () -> String) =
        delegate.e(throwable, TAG, message)
}
