package org.samfun.ktprd.bcert

/** What a `bcert` certificate is for. The leaf of a device chain is [DEVICE]; its issuer is [ISSUER]. */
public enum class BCertType(public val value: Int) {
    UNKNOWN(0x00),
    PC(0x01),
    DEVICE(0x02),
    DOMAIN(0x03),
    ISSUER(0x04),
    CRL_SIGNER(0x05),
    SERVICE(0x06),
    SILVERLIGHT(0x07),
    APPLICATION(0x08),
    METERING(0x09),
    KEY_FILE_SIGNER(0x0A),
    SERVER(0x0B),
    LICENSE_SIGNER(0x0C),
    SECURE_TIME_SERVER(0x0D),
    PROVISIONING_MODEL_AUTH(0x0E),
    ;

    public companion object {
        public fun of(value: Int): BCertType = entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}

/** The tag on a `bcert` attribute, which selects how its body is laid out. */
public enum class BCertObjectType(public val value: Int) {
    BASIC(0x0001),
    DOMAIN(0x0002),
    PC(0x0003),
    DEVICE(0x0004),
    FEATURE(0x0005),
    KEY(0x0006),
    MANUFACTURER(0x0007),
    SIGNATURE(0x0008),
    SILVERLIGHT(0x0009),
    METERING(0x000A),
    EXT_DATA_SIGN_KEY(0x000B),
    EXT_DATA_CONTAINER(0x000C),
    EXT_DATA_SIGNATURE(0x000D),
    EXT_DATA_HWID(0x000E),
    SERVER(0x000F),
    SECURITY_VERSION(0x0010),
    SECURITY_VERSION_2(0x0011),
    UNKNOWN(0xFFFD),
    ;

    public companion object {
        public fun of(value: Int): BCertObjectType = entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}

/** What a key inside a certificate's key list may be used for. */
public enum class BCertKeyUsage(public val value: Int) {
    UNKNOWN(0x00),
    SIGN(0x01),
    ENCRYPT_KEY(0x02),
    SIGN_CRL(0x03),
    ISSUER_ALL(0x04),
    ISSUER_INDIVIDUAL(0x05),
    ISSUER_DEVICE(0x06),
    ISSUER_LINK(0x07),
    ISSUER_DOMAIN(0x08),
    ISSUER_SILVERLIGHT(0x09),
    ISSUER_APPLICATION(0x0A),
    ISSUER_CRL(0x0B),
    ISSUER_METERING(0x0C),
    ISSUER_SIGN_KEY_FILE(0x0D),
    SIGN_KEY_FILE(0x0E),
    ISSUER_SERVER(0x0F),
    ENCRYPT_KEY_SAMPLE_PROTECTION_RC4(0x10),
    RESERVED(0x11),
    ISSUER_SIGN_LICENSE(0x12),
    SIGN_LICENSE(0x13),
    SIGN_RESPONSE(0x14),
    PRND_ENCRYPT_KEY_DEPRECATED(0x15),
    ENCRYPT_KEY_SAMPLE_PROTECTION_AES128CTR(0x16),
    ISSUER_SECURE_TIME_SERVER(0x17),
    ISSUER_PROVISIONING_MODEL_AUTH(0x18),
    ;

    public companion object {
        public fun of(value: Int): BCertKeyUsage = entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}

/** Capabilities a certificate declares. A provisioned device leaf claims the first, ninth and thirteenth. */
public enum class BCertFeature(public val value: Int) {
    TRANSMITTER(0x01),
    RECEIVER(0x02),
    SHARED_CERTIFICATE(0x03),
    SECURE_CLOCK(0x04),
    ANTI_ROLLBACK_CLOCK(0x05),
    RESERVED_METERING(0x06),
    RESERVED_LICENSE_SYNC(0x07),
    RESERVED_SYMMETRIC_OPTIMIZATION(0x08),
    SUPPORTS_CRLS(0x09),
    SERVER_BASIC_EDITION(0x0A),
    SERVER_STANDARD_EDITION(0x0B),
    SERVER_PREMIUM_EDITION(0x0C),
    SUPPORTS_PLAYREADY_3_FEATURES(0x0D),
    DEPRECATED_SECURE_STOP(0x0E),
    UNKNOWN(0xFFFF),
    ;

    public companion object {
        public fun of(value: Int): BCertFeature = entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}

/** Flags on a certificate's basic-info attribute. */
internal object BCertFlag {
    const val EMPTY: Int = 0x00
    const val EXT_DATA_PRESENT: Int = 0x01
}

/** Flags on an individual attribute header. */
internal object BCertObjectFlag {
    const val EMPTY: Int = 0x0000
    const val MUST_UNDERSTAND: Int = 0x0001
    const val CONTAINER: Int = 0x0002
}

/** The only signature type PlayReady certificates use. */
internal const val BCERT_SIGNATURE_TYPE_P256: Int = 0x0001

/** The only key type PlayReady certificates use. */
internal const val BCERT_KEY_TYPE_ECC256: Int = 0x0001
