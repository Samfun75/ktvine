package org.samfun.ktvine.serve

import org.samfun.ktvine.core.Device

/**
 * A caller of the serve API, identified by their secret key.
 *
 * @param username used only for logging; it is never sent to the caller
 * @param devices names of the devices this user may use, as keyed in [ServeConfig.devices]
 */
public class ServeUser(
    public val username: String,
    public val devices: Set<String>,
)

/**
 * What a [ktvineCdm] route serves: which devices exist, and who may use them.
 *
 * A device's private key never leaves the server, which is the point of running one — many
 * clients can share one device without ever holding it.
 *
 * @param devices device name (as it appears in the URL) to the loaded [Device]
 * @param users secret key to the user it authenticates
 * @param forcePrivacyMode reject a challenge whose session has no service certificate set
 * @param serverHeader sent as `Server`; pywidevine's client refuses a server whose header
 *   does not name a `pywidevine serve` version it supports
 */
public class ServeConfig(
    public val devices: Map<String, Device>,
    public val users: Map<String, ServeUser>,
    public val forcePrivacyMode: Boolean = false,
    public val serverHeader: String = DEFAULT_SERVER_HEADER,
) {
    public companion object {
        /** The serve protocol version this module implements, as pywidevine numbers it. */
        public const val PROTOCOL_VERSION: String = "1.8.0"

        /** Names ktvine honestly while declaring the protocol pywidevine's client demands. */
        public const val DEFAULT_SERVER_HEADER: String =
            "ktvine-serve (pywidevine serve v$PROTOCOL_VERSION compatible)"
    }

    internal fun userFor(secretKey: String?): ServeUser? = secretKey?.let { users[it] }

    internal fun deviceFor(user: ServeUser, name: String): Device? = if (name in user.devices) devices[name] else null
}
