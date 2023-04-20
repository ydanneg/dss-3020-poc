package com.ydanneg.util

import java.io.FileNotFoundException
import java.io.FileOutputStream
import java.security.MessageDigest
import java.util.Base64

internal object IOUtils {
    
    fun resourceAsByteArray(resource: String): ByteArray {
        return IOUtils::class.java.getResourceAsStream(resource)?.readBytes() ?: throw FileNotFoundException(resource)
    }

    fun resourceText(resource: String): String {
        return String(resourceAsByteArray(resource))
    }

    fun ByteArray.saveTo(path: String) {
        FileOutputStream(path).use {
            it.write(this)
        }
    }
}


internal object BinUtils {

    fun ByteArray.toSha256(): ByteArray {
        return MessageDigest.getInstance("SHA-256").apply {
            update(this@toSha256)
        }.digest()
    }

    fun ByteArray.toBase64(): String {
        return Base64.getEncoder().encodeToString(this)
    }

}