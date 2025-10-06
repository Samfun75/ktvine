package org.samfun.ktvine.crypto

// Expect/actual crypto API used in common code.
// AES, RSA, HMAC, CMAC primitives and utilities.

expect fun rsaPssSignSha1(privateKeyDer: ByteArray, message: ByteArray): ByteArray
expect fun rsaPssVerifySha1(publicKeyDer: ByteArray, message: ByteArray, signature: ByteArray): Boolean
expect fun rsaOaepDecryptSha1(privateKeyDer: ByteArray, ciphertext: ByteArray): ByteArray
expect fun rsaOaepEncryptSha1(publicKeyDer: ByteArray, plaintext: ByteArray): ByteArray

expect fun aesCbcEncryptNoPadding(key: ByteArray, iv: ByteArray, plaintextNoPad: ByteArray): ByteArray
expect fun aesCbcDecryptNoPadding(key: ByteArray, iv: ByteArray, ciphertext: ByteArray): ByteArray

// Single-block AES-ECB encrypt used by CMAC.
expect fun aesEncryptBlock(key: ByteArray, block16: ByteArray): ByteArray

expect fun hmacSha256(key: ByteArray, data: ByteArray): ByteArray
expect fun randomBytes(size: Int): ByteArray

// Common helpers implemented in commonMain

fun pkcs7Pad(data: ByteArray, blockSize: Int = 16): ByteArray {
    val pad = (blockSize - (data.size % blockSize)).let { if (it == 0) blockSize else it }
    return data + ByteArray(pad) { pad.toByte() }
}

fun pkcs7Unpad(data: ByteArray, blockSize: Int = 16): ByteArray {
    require(data.isNotEmpty() && data.size % blockSize == 0) { "Invalid PKCS7 input" }
    val pad = data.last().toInt() and 0xFF
    require(pad in 1..blockSize && pad <= data.size) { "Invalid PKCS7 padding" }
    // constant-time-ish check
    for (i in 1..pad) require((data[data.size - i].toInt() and 0xFF) == pad) { "Bad PKCS7 padding" }
    return data.copyOfRange(0, data.size - pad)
}

private fun leftShiftOneBit(block: ByteArray): ByteArray {
    val out = ByteArray(block.size)
    var carry = 0
    for (i in block.indices.reversed()) {
        val b = block[i].toInt() and 0xFF
        out[i] = (((b shl 1) or carry) and 0xFF).toByte()
        carry = (b ushr 7) and 0x01
    }
    return out
}

private fun xor(a: ByteArray, b: ByteArray): ByteArray {
    val out = ByteArray(a.size)
    for (i in a.indices) out[i] = (a[i].toInt() xor b[i].toInt()).toByte()
    return out
}

fun cmacAes(key: ByteArray, data: ByteArray): ByteArray {
    // RFC 4493
    val blockSize = 16
    val zero = ByteArray(blockSize)
    val L = aesEncryptBlock(key, zero)
    val Rb = ByteArray(blockSize) { 0 }
    Rb[blockSize - 1] = 0x87.toByte()

    val K1 = run {
        val tmp = leftShiftOneBit(L)
        if ((L[0].toInt() and 0x80) != 0) xor(tmp, Rb) else tmp
    }
    val K2 = run {
        val tmp = leftShiftOneBit(K1)
        if ((K1[0].toInt() and 0x80) != 0) xor(tmp, Rb) else tmp
    }

    val n = if (data.isEmpty()) 0 else (data.size + blockSize - 1) / blockSize
    val lastBlockComplete = (n > 0 && (data.size % blockSize == 0))

    val Mlast = if (n == 0) {
        xor(pkcs7Pad(ByteArray(0), blockSize), K2)
    } else {
        val start = (n - 1) * blockSize
        val last = data.copyOfRange(start, data.size)
        if (lastBlockComplete) xor(last, K1) else xor(pkcs7Pad(last, blockSize), K2)
    }

    var X = ByteArray(blockSize)
    val rounds = if (n == 0) 0 else (n - 1)
    for (i in 0 until rounds) {
        val start = i * blockSize
        val Mi = data.copyOfRange(start, start + blockSize)
        X = aesEncryptBlock(key, xor(X, Mi))
    }

    return aesEncryptBlock(key, xor(X, Mlast))
}
