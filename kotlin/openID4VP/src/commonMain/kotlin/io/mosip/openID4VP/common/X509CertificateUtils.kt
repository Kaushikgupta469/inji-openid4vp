package io.mosip.openID4VP.common

import org.bouncycastle.jce.provider.BouncyCastleProvider
import java.io.ByteArrayInputStream
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

private val bouncyCastleProvider by lazy { BouncyCastleProvider() }

private const val KEY_USAGE_KEY_CERT_SIGN = 5

internal fun parseX509Certificate(der: ByteArray): X509Certificate {
    val certificate = CertificateFactory.getInstance("X.509", bouncyCastleProvider)
        .generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
    if (certificate == null || !certificate.encoded.contentEquals(der)) {
        throw CertificateException("Input is not exactly one DER-encoded X.509 certificate")
    }
    return certificate
}

internal fun validateCertificationPath(
    certificateChain: List<X509Certificate>,
    trustAnchors: List<X509Certificate>,
) {
    val parameters = PKIXParameters(trustAnchors.map { TrustAnchor(it, null) }.toSet()).apply {
        isRevocationEnabled = false
    }
    val trustAnchorIndex = certificateChain.drop(1).indexOfFirst { it in trustAnchors }
    val certificationPathCertificates =
        if (trustAnchorIndex == -1) certificateChain else certificateChain.take(trustAnchorIndex + 1)
    val certificationPath = CertificateFactory.getInstance("X.509", bouncyCastleProvider)
        .generateCertPath(certificationPathCertificates)
    val result = CertPathValidator.getInstance("PKIX", bouncyCastleProvider)
        .validate(certificationPath, parameters) as PKIXCertPathValidatorResult
    val trustAnchor = result.trustAnchor.trustedCert
    if (trustAnchor != certificateChain.first()) {
        if (trustAnchor.basicConstraints < 0) {
            throw CertPathValidatorException("Trust anchor ${trustAnchor.subjectX500Principal} is not a CA certificate")
        }
        if (trustAnchor.keyUsage?.get(KEY_USAGE_KEY_CERT_SIGN) == false) {
            throw CertPathValidatorException(
                "Key usage of trust anchor ${trustAnchor.subjectX500Principal} does not allow keyCertSign"
            )
        }
    }
}
