package com.ydanneg.dss.sid

import ee.sk.smartid.CertificateRequestBuilder
import ee.sk.smartid.HashType
import ee.sk.smartid.SignableHash
import ee.sk.smartid.SignatureRequestBuilder
import ee.sk.smartid.SmartIdCertificate
import ee.sk.smartid.SmartIdClient
import ee.sk.smartid.SmartIdSignature
import ee.sk.smartid.rest.dao.Interaction
import ee.sk.smartid.rest.dao.SemanticsIdentifier
import ee.sk.smartid.rest.dao.SemanticsIdentifier.CountryCode
import ee.sk.smartid.rest.dao.SessionStatus
import java.util.concurrent.TimeUnit

internal class SmartIdDemoService(config: SmartIdServiceConfiguration) {

    data class SmartIdServiceConfiguration(
        val relyingPartyName: String,
        val relyingPartyUUID: String,
        val hostUrl: String,
        val responseSocketOpenTime: Int,
        val certPem: String,
        val identityNumber: String
    )

    private val client: SmartIdClient = SmartIdClient().apply {
        relyingPartyName = config.relyingPartyName
        relyingPartyUUID = config.relyingPartyUUID
        setHostUrl(config.hostUrl)
        setSessionStatusResponseSocketOpenTime(TimeUnit.SECONDS, config.responseSocketOpenTime.toLong())
        setTrustedCertificates(config.certPem)
    }

    fun createCertificateChoiceSession(countryCode: CountryCode, identityNumber: String): String {
        return certificateRequestBuilder()
            .withSemanticsIdentifier(
                SemanticsIdentifier(
                    SemanticsIdentifier.IdentityType.PNO,
                    countryCode,
                    identityNumber
                )
            )
            .initiateCertificateChoice()
    }

    fun createCertificateChoiceSession(documentNumber: String): String {
        return certificateRequestBuilder()
            .withDocumentNumber(documentNumber)
            .initiateCertificateChoice()
    }

    fun tryGetSignature(hashToSignBase64: String, message: String, smartIdCertificate: SmartIdCertificate, attempts: Int = 3): SmartIdSignature? {
        val signatureSessionId = createSignatureSession(
            hashToSignBase64,
            message,
            smartIdCertificate.documentNumber
        )
        var attemptsLeft = attempts
        var smartIdSignature: SmartIdSignature? = null
        while (smartIdSignature == null && attemptsLeft-- > 0) {
            smartIdSignature = getSignature(signatureSessionId)
        }
        return smartIdSignature
    }

    fun getSignature(sessionId: String): SmartIdSignature? {
        val sessionStatus = getSessionStatus(sessionId)
        return if ("COMPLETE" == sessionStatus.state) {
            signatureRequestBuilder().createSmartIdSignature(sessionStatus)
        } else null
    }

    fun tryGetCertificate(countryCode: CountryCode, identityNumber: String, attempts: Int = 3): SmartIdCertificate? {
        val certificateChoiceSessionId = createCertificateChoiceSession(countryCode, identityNumber)
        var smartIdCertificate: SmartIdCertificate? = null
        var attemptsLeft = attempts
        while (smartIdCertificate == null && attemptsLeft-- > 0) {
            smartIdCertificate = getCertificate(certificateChoiceSessionId)
        }
        return smartIdCertificate
    }

    fun getCertificate(sessionId: String): SmartIdCertificate? {
        val sessionStatus = getSessionStatus(sessionId)
        return if ("COMPLETE" == sessionStatus.state) {
            certificateRequestBuilder().createSmartIdCertificate(sessionStatus)
        } else null
    }

    fun createSignatureSession(hashToSignBase64: String, message: String, documentNumber: String): String {
        return signatureRequestBuilder()
            .withAllowedInteractionsOrder(listOf(Interaction.displayTextAndPIN(message)))
            .withSignableHash(buildSignableHash(hashToSignBase64))
            .withDocumentNumber(documentNumber)
            .initiateSigning()
    }

    fun getSessionStatus(sessionId: String): SessionStatus {
        return client.smartIdConnector.getSessionStatus(sessionId)
    }

    private fun certificateRequestBuilder(): CertificateRequestBuilder {
        return client.certificate
    }

    private fun signatureRequestBuilder(): SignatureRequestBuilder {
        return client.createSignature()
    }

    private fun buildSignableHash(hashToSignBase64: String): SignableHash {
        val signableHash = SignableHash()
        signableHash.hashInBase64 = hashToSignBase64
        signableHash.hashType = HashType.SHA256
        return signableHash
    }
}