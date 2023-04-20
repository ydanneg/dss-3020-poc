package com.ydanneg.dss

import com.ydanneg.dss.sid.SmartIdDemoService
import com.ydanneg.util.BinUtils.toBase64
import com.ydanneg.util.BinUtils.toSha256
import com.ydanneg.util.IOUtils
import com.ydanneg.util.IOUtils.saveTo
import ee.sk.smartid.rest.dao.SemanticsIdentifier
import eu.europa.esig.dss.alert.SilentOnStatusAlert
import eu.europa.esig.dss.asic.xades.ASiCWithXAdESSignatureParameters
import eu.europa.esig.dss.asic.xades.signature.ASiCWithXAdESService
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidator
import eu.europa.esig.dss.asic.xades.validation.ASiCContainerWithXAdESValidatorFactory
import eu.europa.esig.dss.enumerations.ASiCContainerType
import eu.europa.esig.dss.enumerations.DigestAlgorithm
import eu.europa.esig.dss.enumerations.EncryptionAlgorithm
import eu.europa.esig.dss.enumerations.SignatureAlgorithm
import eu.europa.esig.dss.enumerations.SignatureLevel
import eu.europa.esig.dss.model.DSSDocument
import eu.europa.esig.dss.model.InMemoryDocument
import eu.europa.esig.dss.model.SignatureValue
import eu.europa.esig.dss.model.x509.CertificateToken
import eu.europa.esig.dss.service.ocsp.OnlineOCSPSource
import eu.europa.esig.dss.spi.x509.aia.DefaultAIASource
import eu.europa.esig.dss.validation.CommonCertificateVerifier
import eu.europa.esig.dss.validation.SignedDocumentValidator
import io.kotest.matchers.shouldBe
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.slf4j.LoggerFactory
import java.security.Security
import java.security.cert.X509Certificate
import java.util.Date
import kotlin.test.Test

class XAdESSignatureTest {

    init {
        Security.addProvider(BouncyCastleProvider())
    }

    private val logger = LoggerFactory.getLogger("Test")


    private val asicDocumentValidatorFactory = object : ASiCContainerWithXAdESValidatorFactory() {
        override fun create(document: DSSDocument): SignedDocumentValidator {
            return super.create(document).apply {
                setCertificateVerifier(CommonCertificateVerifier())
            }
        }
    }

    @Test
    fun testXAdESSignatureWithDocxFile() {
        val mimeType = CustomMimeTypeLoader.CustomMimeType.DOCX
        val document1 = InMemoryDocument(
            IOUtils.resourceAsByteArray("/sample.docx"),
            "sample1.docx",
            mimeType
        )

        logger.info("Signing #1")
        val onceSignedContainer = signDSSXAdESWithSmartId(listOf(document1))
        onceSignedContainer.saveTo("output/testXAdESSignatureWithDocxFile-1.asice")
        val validator1 = asicDocumentValidatorFactory.create(onceSignedContainer) as ASiCContainerWithXAdESValidator
        validator1.containerType shouldBe ASiCContainerType.ASiC_E

        logger.info("Signing #2")
        val twiceSignedContainer = signDSSXAdESWithSmartId(listOf(onceSignedContainer))
        twiceSignedContainer.saveTo("output/testXAdESSignatureWithDocxFile-2.asice")
        val validator2 = asicDocumentValidatorFactory.create(twiceSignedContainer) as ASiCContainerWithXAdESValidator
        validator2.containerType shouldBe ASiCContainerType.ASiC_E
    }

    private fun InMemoryDocument.saveTo(path: String) = bytes.saveTo(path)

    private fun buildService(): ASiCWithXAdESService {
        val certificateVerifier = CommonCertificateVerifier().apply {
            ocspSource = OnlineOCSPSource()
            aiaSource = DefaultAIASource()
            crlSource = null
            alertOnMissingRevocationData = SilentOnStatusAlert()
            alertOnRevokedCertificate = SilentOnStatusAlert()
            alertOnExpiredSignature = SilentOnStatusAlert()
            alertOnInvalidTimestamp = SilentOnStatusAlert()
            alertOnUncoveredPOE = SilentOnStatusAlert()
            alertOnNoRevocationAfterBestSignatureTime = SilentOnStatusAlert()
        }
        return ASiCWithXAdESService(certificateVerifier)
    }

    private fun buildSignatureParameters(
        signingDate: Date,
        certificate: X509Certificate,
        certificates: List<X509Certificate>
    ): ASiCWithXAdESSignatureParameters {
        return ASiCWithXAdESSignatureParameters().apply {
            aSiC().containerType = ASiCContainerType.ASiC_E
            bLevel().signingDate = signingDate
            signatureLevel = SignatureLevel.XAdES_BASELINE_B
            digestAlgorithm = DigestAlgorithm.SHA256
            signingCertificate = CertificateToken(certificate)
            certificateChain = certificates.map { CertificateToken(it) }
            isSignWithExpiredCertificate = true
        }
    }

    private fun signDSSXAdESWithSmartId(documents: List<DSSDocument>): InMemoryDocument {
        val config = demoConfig()
        val smartIdService = SmartIdDemoService(config)
        val aSiCWithXAdESService = buildService()

        logger.info("Waiting for Smart-Id certificate...")
        val smartIdCertificate = smartIdService.tryGetCertificate(
            countryCode = SemanticsIdentifier.CountryCode.EE,
            identityNumber = config.identityNumber,
            attempts = 3
        )!!
        logger.info("Certificate: ${smartIdCertificate.certificate.subjectX500Principal}")

        val certificate = smartIdCertificate.certificate
        val signingDate = Date()

        logger.info("Calculating XAdES DataToSign...")
        val dataToSign = aSiCWithXAdESService.getDataToSign(
            documents[0],
            buildSignatureParameters(signingDate, certificate, listOf(certificate))
        ).bytes.toSha256().toBase64()
        logger.info("DataToSign: $dataToSign")

        logger.info("Waiting for Smart-Id signature...")
        val smartIdSignature = smartIdService.tryGetSignature(
            hashToSignBase64 = dataToSign,
            message = "Sign test document.",
            smartIdCertificate = smartIdCertificate,
            attempts = 3
        )!!
        logger.info("Signature: ${smartIdSignature.valueInBase64}")

        val signatureValue =
            SignatureValue(
                SignatureAlgorithm.getAlgorithm(EncryptionAlgorithm.forKey(certificate.publicKey), DigestAlgorithm.SHA256),
                smartIdSignature.value
            )

        logger.info("Adding XAdES signature...")
        val updatedWithSignature =
            aSiCWithXAdESService.signDocument(documents[0], buildSignatureParameters(signingDate, certificate, listOf(certificate)), signatureValue)
        logger.info("XAdES signature added successfully")
        return InMemoryDocument(updatedWithSignature.openStream(), updatedWithSignature.name, updatedWithSignature.mimeType)
    }

    private fun demoConfig(): SmartIdDemoService.SmartIdServiceConfiguration {
        return SmartIdDemoService.SmartIdServiceConfiguration(
            "DEMO",
            "00000000-0000-0000-0000-000000000000",
            "https://sid.demo.sk.ee/smart-id-rp/v2/",
            5,
            IOUtils.resourceText("/certs/sid_demo_sk_ee_2022_PEM.crt"),
            identityNumber = "30303039914"
        )
    }
}