@file:OptIn(DelicateCryptographyApi::class)

package org.samfun.ktvine.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.DelicateCryptographyApi
import dev.whyoleg.cryptography.algorithms.*
import java.security.spec.X509EncodedKeySpec
import kotlin.random.Random

val crypto = CryptographyProvider.Default

suspend fun rsaPssSignSha1(privateKeyDer: ByteArray, data: ByteArray): ByteArray {
    val rsa = crypto.get(RSA.PSS)
    val privateKey = rsa.privateKeyDecoder(SHA1).decodeFromByteArray(
        RSA.PrivateKey.Format.DER.PKCS1,
        privateKeyDer
    )
    return privateKey.signatureGenerator().generateSignature(data)
}

suspend fun rsaPssVerifySha1(publicKeyDer: ByteArray, data: ByteArray, signature: ByteArray): Boolean {
    val rsa = crypto.get(RSA.PSS)
    val publicKey =
        rsa.publicKeyDecoder(SHA1).decodeFromByteArray(
            RSA.PublicKey.Format.DER,
            X509EncodedKeySpec(publicKeyDer).encoded
        )
    return publicKey.signatureVerifier().tryVerifySignature(data, signature)
}

suspend fun rsaOaepEncrypt(publicKeyDer: ByteArray, data: ByteArray): ByteArray {
    val rsa = crypto.get(RSA.OAEP)
    val publicKey = rsa.publicKeyDecoder(SHA1).decodeFromByteArray(
        RSA.PublicKey.Format.DER,
        X509EncodedKeySpec(publicKeyDer).encoded
    )
    return publicKey.encryptor().encrypt(data)
}

suspend fun rsaOaepDecrypt(privateKeyDer: ByteArray, data: ByteArray): ByteArray {
    val rsa = crypto.get(RSA.OAEP)
    val privateKey =
        rsa.privateKeyDecoder(SHA1).decodeFromByteArray(
            RSA.PrivateKey.Format.DER.PKCS1,
            privateKeyDer
        )
    return privateKey.decryptor().decrypt(data)
}

suspend fun aesCmac(key: ByteArray, data: ByteArray): ByteArray {
    val cmac = crypto.get(AES.CMAC)
    val generator = cmac.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, key).signatureGenerator()
    return generator.generateSignature(data)
}

suspend fun aesCbcDecrypt(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray {
    val cbc = crypto.get(AES.CBC)
    val decryptor = cbc.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, key).cipher(false)
    return decryptor.decryptWithIv(iv, data)
}

// Alias to match existing call sites expecting explicit no-padding naming
suspend fun aesCbcDecryptNoPadding(key: ByteArray, iv: ByteArray, data: ByteArray): ByteArray =
    aesCbcDecrypt(key, iv, data)

// AES-CBC encrypt without internal padding. Provide PKCS#7 padded plaintext.
suspend fun aesCbcEncryptNoPadding(key: ByteArray, iv: ByteArray, plaintextNoPad: ByteArray): ByteArray {
    val cbc = crypto.get(AES.CBC)
    val encryptor = cbc.keyDecoder().decodeFromByteArray(AES.Key.Format.RAW, key).cipher(padding = false)
    return encryptor.encryptWithIv(iv, plaintextNoPad)
}

suspend fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray {
    val hmac = crypto.get(HMAC)
    val generator = hmac.keyDecoder(SHA256).decodeFromByteArray(HMAC.Key.Format.RAW,key).signatureGenerator()
    return generator.generateSignature(data)
}

fun randomBytes(count: Int): ByteArray {
    return Random.nextBytes(count)
}

// PKCS#7 padding helpers
fun pkcs7Pad(data: ByteArray, blockSize: Int = 16): ByteArray {
    require(blockSize in 1..255) { "Invalid block size $blockSize" }
    val padLen = blockSize - (data.size % blockSize)
    val padding = ByteArray(padLen) { padLen.toByte() }
    return data + padding
}

fun pkcs7Unpad(data: ByteArray, blockSize: Int = 16): ByteArray {
    require(data.isNotEmpty()) { "Cannot unpad empty data" }
    require(data.size % blockSize == 0) { "Data length must be a multiple of block size" }
    val padLen = data.last().toInt() and 0xFF
    for (i in 1..padLen) {
        if ((data[data.size - i].toInt() and 0xFF) != padLen) {
            // Not padded, or invalid padding
            return data
        }
    }
    return data.copyOf(data.size - padLen)
}
