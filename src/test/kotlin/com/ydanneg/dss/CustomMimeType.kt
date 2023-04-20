package com.ydanneg.dss

import eu.europa.esig.dss.enumerations.MimeType
import eu.europa.esig.dss.enumerations.MimeTypeLoader


class CustomMimeTypeLoader : MimeTypeLoader {

    override fun fromMimeTypeString(mimeTypeString: String): MimeType? = CustomMimeType.values().find { mimeType ->
        mimeType.mimeTypeString.equals(mimeTypeString, ignoreCase = true)
    }

    override fun fromFileExtension(fileExtension: String): MimeType? = CustomMimeType.values().find { mimeType ->
        mimeType.extensions.any { fileExtension.equals(it, ignoreCase = true) }
    }

    enum class CustomMimeType(private val mimeTypeString: String, vararg extensions: String) : MimeType {
        DOCX("application/vnd.openxmlformats-officedocument.wordprocessingml.document", "docx");

        internal val extensions: List<String> = extensions.asList()

        override fun getMimeTypeString(): String {
            return mimeTypeString
        }

        override fun getExtension(): String? = extensions.firstOrNull()
    }
}