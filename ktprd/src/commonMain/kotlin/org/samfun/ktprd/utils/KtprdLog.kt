package org.samfun.ktprd.utils

import co.touchlab.kermit.Logger
import co.touchlab.kermit.Severity
import co.touchlab.kermit.loggerConfigInit
import co.touchlab.kermit.platformLogWriter

/**
 * Every log line ktprd emits goes through here.
 *
 * This is deliberately separate from ktvine's sink rather than routed into it: the two CDMs are
 * separate artifacts with separate log tags, and a caller using only one should not have to
 * configure the other. The emit methods are public because `ktprd-remote` and `ktprd-serve` log
 * through them from their own modules.
 *
 * ktprd is quiet by default: only [Severity.Warn] and above reach the platform log.
 */
public object KtprdLog {

    internal const val TAG: String = "ktprd"

    private var delegate: Logger = loggerFor(Severity.Warn)

    private fun loggerFor(minSeverity: Severity): Logger = Logger(
        config = loggerConfigInit(platformLogWriter(), minSeverity = minSeverity),
        tag = TAG,
    )

    /** Raise or lower how much ktprd logs. Defaults to [Severity.Warn]. */
    public fun setMinSeverity(severity: Severity) {
        delegate = loggerFor(severity)
    }

    /** Route ktprd's logging into an existing Kermit [Logger]. */
    public fun setLogger(logger: Logger) {
        delegate = logger
    }

    /** Restore the default sink and severity. */
    public fun reset() {
        delegate = loggerFor(Severity.Warn)
    }

    // Not inline: forwarding an inline lambda parameter on to Kermit's own inline methods is not
    // allowed, and the allocation is irrelevant next to a license exchange.
    public fun v(message: () -> String): Unit = delegate.v(null, TAG, message)

    public fun d(message: () -> String): Unit = delegate.d(null, TAG, message)

    public fun w(message: () -> String): Unit = delegate.w(null, TAG, message)

    public fun e(throwable: Throwable? = null, message: () -> String): Unit = delegate.e(throwable, TAG, message)
}
