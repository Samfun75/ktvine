package org.samfun.ktprd.core

import org.samfun.ktvine.utils.toHexString
import kotlin.uuid.Uuid

/** How the content key is meant to be applied to the media. */
public enum class PlayreadyKeyType(public val value: Int) {
    INVALID(0x0000),
    AES_128_CTR(0x0001),
    RC4_CIPHER(0x0002),
    AES_128_ECB(0x0003),
    COCKTAIL(0x0004),
    AES_128_CBC(0x0005),
    KEY_EXCHANGE(0x0006),
    UNKNOWN(0xFFFF),
    ;

    public companion object {
        public fun of(value: Int): PlayreadyKeyType = entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}

/** How the license encrypted the content key to the device. */
public enum class PlayreadyCipherType(public val value: Int) {
    INVALID(0x0000),
    RSA_1024(0x0001),
    CHAINED_LICENSE(0x0002),
    ECC_256(0x0003),
    ECC_256_WITH_KZ(0x0004),
    TEE_TRANSIENT(0x0005),
    ECC_256_VIA_SYMMETRIC(0x0006),
    UNKNOWN(0xFFFF),
    ;

    public companion object {
        public fun of(value: Int): PlayreadyCipherType = entries.firstOrNull { it.value == value } ?: UNKNOWN
    }
}

/**
 * A decrypted PlayReady content key.
 *
 * [kid] is held big-endian, matching `cenc:default_KID` and ktvine's Widevine keys; the
 * little-endian GUID form PlayReady stores is converted on the way in.
 *
 * This is deliberately not ktvine's `Key`, whose type is a Widevine protobuf enum that cannot
 * describe [PlayreadyKeyType].
 */
public class PlayreadyKey(
    public val kid: Uuid,
    public val key: ByteArray,
    public val keyType: PlayreadyKeyType,
    public val cipherType: PlayreadyCipherType,
    public val keyLength: Int,
) {
    // A data class would compare `key` by identity.
    override fun toString(): String =
        "PlayreadyKey(kid=$kid, type=$keyType, cipherType=$cipherType, key=${key.toHexString()})"

    override fun equals(other: Any?): Boolean = other is PlayreadyKey &&
        kid == other.kid &&
        key.contentEquals(other.key) &&
        keyType == other.keyType &&
        cipherType == other.cipherType &&
        keyLength == other.keyLength

    override fun hashCode(): Int {
        var result = kid.hashCode()
        result = 31 * result + key.contentHashCode()
        result = 31 * result + keyType.hashCode()
        result = 31 * result + cipherType.hashCode()
        result = 31 * result + keyLength
        return result
    }
}
