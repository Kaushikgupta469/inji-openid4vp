package io.mosip.openID4VP.common

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Base64
import java.io.ByteArrayInputStream
import java.security.GeneralSecurityException
import java.security.cert.CertPathValidator
import java.security.cert.CertPathValidatorException
import java.security.cert.CertificateException
import java.security.cert.CertificateFactory
import java.security.cert.PKIXCertPathValidatorResult
import java.security.cert.PKIXParameters
import java.security.cert.TrustAnchor
import java.security.cert.X509Certificate

// BouncyCastle on every platform, so keys are typed the same way on Android and the JVM
private val bouncyCastleProvider by lazy { BouncyCastleProvider() }

// Exactly one DER-encoded certificate, with no trailing data
internal fun parseX509Certificate(der: ByteArray): X509Certificate {
    val certificate = CertificateFactory.getInstance("X.509", bouncyCastleProvider)
        .generateCertificate(ByteArrayInputStream(der)) as? X509Certificate
    if (certificate == null || !certificate.encoded.contentEquals(der)) {
        throw CertificateException("Input is not exactly one DER-encoded X.509 certificate")
    }
    return certificate
}

// RFC 5280 path validation of the chain (leaf first) to one of the trust anchors; revocation is not checked
internal fun validateCertificationPath(
    certificateChain: List<X509Certificate>,
    trustAnchors: List<X509Certificate>,
) {
    val parameters = PKIXParameters(trustAnchors.map { TrustAnchor(it, null) }.toSet()).apply {
        isRevocationEnabled = false
    }
    // The path ends before a trust anchor that the chain itself carries
    val trustAnchorIndex = certificateChain.drop(1).indexOfFirst { it in trustAnchors }
    val certificationPathCertificates =
        if (trustAnchorIndex == -1) certificateChain else certificateChain.take(trustAnchorIndex + 1)
    val certificationPath = CertificateFactory.getInstance("X.509", bouncyCastleProvider)
        .generateCertPath(certificationPathCertificates)
    val result = CertPathValidator.getInstance("PKIX", bouncyCastleProvider)
        .validate(certificationPath, parameters) as PKIXCertPathValidatorResult
    val trustAnchor = result.trustAnchor.trustedCert
    if (trustAnchor != certificateChain.first() && trustAnchor.basicConstraints < 0) {
        throw CertPathValidatorException("Trust anchor ${trustAnchor.subjectX500Principal} is not a CA certificate")
    }
}

internal fun X509Certificate.isSelfSigned(): Boolean {
    if (subjectX500Principal != issuerX500Principal) return false
    return try {
        verify(publicKey)
        true
    } catch (e: GeneralSecurityException) {
        false
    }
}

// The shared encodeToBase64Url is not URL-safe on Android below API 26
internal fun encodeToBase64UrlWithoutPadding(data: ByteArray): String {
    return Base64.toBase64String(data).trimEnd('=').replace('+', '-').replace('/', '_')
}
