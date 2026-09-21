package org.samfun.ktprd.serve

import org.samfun.ktprd.core.PlayreadyDevice

/** A caller of the served CDM, and the devices they may use. */
public class PlayreadyServeUser(public val username: String, public val devices: Set<String>)

/**
 * What a served PlayReady CDM offers and to whom.
 *
 * @param devices the devices this server holds, keyed by the name clients address them under
 * @param users the callers, keyed by the secret they authenticate with
 * @param serverHeader the `Server` header; clients look for "playready serve" in it
 */
public class PlayreadyServeConfig(
    public val devices: Map<String, PlayreadyDevice>,
    public val users: Map<String, PlayreadyServeUser>,
    public val serverHeader: String = DEFAULT_SERVER_HEADER,
) {
    public companion object {
        /** The pyplayready serve release this protocol matches. */
        public const val PROTOCOL_VERSION: String = "0.8.1"

        public const val DEFAULT_SERVER_HEADER: String =
            "ktprd-serve (pyplayready serve v$PROTOCOL_VERSION compatible)"
    }

    internal fun userFor(secretKey: String?): PlayreadyServeUser? = secretKey?.let { users[it] }

    internal fun deviceFor(user: PlayreadyServeUser, name: String): PlayreadyDevice? =
        if (name in user.devices) devices[name] else null
}
