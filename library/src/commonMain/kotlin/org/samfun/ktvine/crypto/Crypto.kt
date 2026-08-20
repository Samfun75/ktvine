@file:OptIn(DelicateCryptographyApi::class)

package org.samfun.ktvine.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.AES
import dev.whyoleg.cryptography.algorithms.HMAC
import dev.whyoleg.cryptography.algorithms.RSA
import dev.whyoleg.cryptography.algorithms.SHA1
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.random.CryptographyRandom
import org.samfun.ktvine.utils.ValueException

private val crypto = CryptographyProvider.Default

/** Sign data with RSA-PSS (SHA-1) using a PKCS#1 DER private key. */
public suspend fun rsaPssSignSha1(privateKeyDer: ByteArray, data: ByteArray): ByteArray {
    val rsa = crypto.get(RSA.PSS)
    val privateKey = rsa.privateKeyDecoder(SHA1).decodeFromByteArray(
        RSA.PrivateKey.Format.DER.PKCS1,
        privateKeyDer,
    )
    return privateKey.signatureGenerator().generateSignature(data)
}

/** Verify an RSA-PSS (SHA-1) signature using an X.509 DER public key. */
public suspend fun rsaPssVerifySha1(publicKeyDer: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
    val rsa = crypto.get(RSA.PSS)
    val publicKey =
        rsa.publicKeyDecoder(SHA1).decodeFromByteArray(
            RSA.PublicKey.Format.DER.PKCS1,
            publicKeyDer,
        )
    return publicKey.signatureVerifier().tryVerifySignature(data, signature)
}

/** Encrypt with RSA-OAEP (SHA-1) using an X.509 DER public key. */
public suspend fun rsaOaepEncrypt(publicKeyDer: ByteArray, data: ByteArray): ByteArray {
    val rsa = crypto.get(RSA.OAEP)
    val publicKey = rsa.publicKeyDecoder(SHA1).decodeFromByteArray(
        RSA.PublicKey.Format.DER.PKCS1,
        publicKeyDer,
    )
    return publicKey.encryptor().encrypt(data)
}

/** Decrypt with RSA-OAEP (SHA-1) using a PKCS#1 DER private key. */
public suspend fun rsaOaepDecrypt(privateKeyDer: ByteArray, data: ByteArray): ByteArray {
    val rsa = crypto.get(RSA.OAEP)
    val privateKey =
        rsa.privateKeyDecoder(SHA1).decodeFromByteArray(
            RSA.PrivateKey.Format.DER.PKCS1,
            privateKeyDer,
        )
    return privateKey.decryptor().decrypt(data)
}

private val ZERO_IV = ByteArray(16)
private const val CMAC_RB = 0x87

/**
 * Compute AES-CMAC (RFC 4493) over [data] with a raw AES [key].
 *
 * Implemented here rather than via `AES.CMAC` because no provider offers CMAC on every
 * target: BouncyCastle covers JVM/Android and OpenSSL3 covers Linux, but neither Apple
 * provider in cryptography-kotlin 0.5.0 has it. CMAC is CBC-MAC with a tweaked final
 * block, so AES-CBC — which every provider does have — is enough to build it.
 */
public suspend fun aesCmac(key: ByteArray, data: ByteArray): ByteArray {
    // L = AES-ECB(K, 0^128); a single CBC block with a zero IV is the same thing.
    val l = aesCbcEncryptNoPadding(key, ZERO_IV, ZERO_IV)
    val k1 = shiftLeftWithRb(l)
    val k2 = shiftLeftWithRb(k1)

    val complete = data.isNotEmpty() && data.size % 16 == 0
    val blockCount = if (complete) data.size / 16 else data.size / 16 + 1

    val message = ByteArray(blockCount * 16)
    data.copyInto(message)

    val lastStart = (blockCount - 1) * 16
    if (!complete) {
        // Pad the final partial block with 0x80 then zeros.
        message[data.size] = 0x80.toByte()
    }
    val subkey = if (complete) k1 else k2
    for (i in 0 until 16) {
        message[lastStart + i] = (message[lastStart + i].toInt() xor subkey[i].toInt()).toByte()
    }

    // CBC over the whole message with a zero IV chains the blocks; the MAC is the last one.
    val encrypted = aesCbcEncryptNoPadding(key, ZERO_IV, message)
    return encrypted.copyOfRange(encrypted.size - 16, encrypted.size)
}

/** One-bit left shift, XORing in the Rb constant when the high bit was set (RFC 4493 §2.3). */
private fun shiftLeftWithRb(input: ByteArray): ByteArray {
    val out = ByteArray(16)
    var carry = 0
    for (i in 15 downTo 0) {
        val value = input[i].toInt() and 0xFF
        out[i] = ((value shl 1) or carry).toByte()
        carry = value ushr 7
    }
    if ((input[0].toInt() and 0x80) != 0) {
        out[15] = (out[15].toInt() xor CMAC_RB).toByte()
    }
    return out
}

/** AES-CBC decrypt with PKCS#7 padding handling determined by cipher. */
public suspend fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
    val cbc = crypto.get(AES.CBC)
    val decryptor = cbc.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, key).cipher(false)
    return decryptor.decryptWithIv(iv, data)
}

/** Alias to match existing call sites expecting explicit no-padding naming. */
public suspend fun aesCbcDecryptNoPadding(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
    aesCbcDecrypt(key, iv, data)

/** AES-CBC encrypt without internal padding. Provide PKCS#7 padded plaintext. */
public suspend fun aesCbcEncryptNoPadding(key: ByteArray, iv: ByteArray, plaintextNoPad: ByteArray): ByteArray {
    val cbc = crypto.get(AES.CBC)
    val encryptor = cbc.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, key).cipher(padding = false)
    return encryptor.encryptWithIv(iv, plaintextNoPad)
}

/** Compute HMAC-SHA256 over [data] with [key]. */
public suspend fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val hmac = crypto.get(HMAC)
    val generator = hmac.keyDecoder(SHA256).decodeFromByteArray(HMAC.Key.Format.RAW, key).signatureGenerator()
    return generator.generateSignature(data)
}

/** Generate [count] cryptographically strong random bytes. */
public fun randomBytes(count: Int): ByteArray = CryptographyRandom.nextBytes(count)

/** Generate a cryptographically strong random [Int] in `[from, until)`. */
public fun randomInt(from: Int, until: Int): Int = CryptographyRandom.nextInt(from, until)

/**
 * Compare two byte arrays without an early exit, so the position of the first differing
 * byte is not observable through timing. Lengths are still compared directly.
 */
public fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var diff = 0
    for (i in a.indices) diff = diff or (a[i].toInt() xor b[i].toInt())
    return diff == 0
}

/** Apply PKCS#7 padding to [data] for [blockSize] bytes (default 16). */
public fun pkcs7Pad(data: ByteArray, blockSize: Int = 16): ByteArray {
    if (blockSize !in 1..255) throw ValueException("Invalid block size $blockSize")
    val padLen = blockSize - (data.size % blockSize)
    val padding = ByteArray(padLen) { padLen.toByte() }
    return data + padding
}

/**
 * Remove PKCS#7 padding from [data].
 *
 * @throws ValueException if the padding is absent or malformed, matching pywidevine's
 *   `Padding.unpad`. Returning the input unchanged would hand back a failed decrypt as
 *   if it were a content key.
 */
public fun pkcs7Unpad(data: ByteArray, blockSize: Int = 16): ByteArray {
    if (blockSize !in 1..255) throw ValueException("Invalid block size $blockSize")
    if (data.isEmpty()) throw ValueException("Cannot unpad empty data")
    if (data.size % blockSize != 0) {
        throw ValueException("Data length ${data.size} is not a multiple of block size $blockSize")
    }

    val padLen = data.last().toInt() and 0xFF

    // Always inspect a full block so a bad decrypt cannot be told apart by timing.
    var bad = if (padLen in 1..blockSize) 0 else 1
    for (i in 1..blockSize) {
        val actual = data[data.size - i].toInt() and 0xFF
        val inPadding = if (i <= padLen) 1 else 0
        bad = bad or (inPadding * (actual xor padLen))
    }
    if (bad != 0) throw ValueException("Invalid PKCS#7 padding")

    return data.copyOf(data.size - padLen)
}
