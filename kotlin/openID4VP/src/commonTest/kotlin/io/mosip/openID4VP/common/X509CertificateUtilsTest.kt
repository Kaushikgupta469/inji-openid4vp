package io.mosip.openID4VP.common

import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.VerifierKeyType
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.X509HashTestData
import java.security.GeneralSecurityException
import java.security.cert.CertificateException
import java.security.interfaces.ECPublicKey
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class X509CertificateUtilsTest {

    private val verifier = X509HashTestData.createVerifierCredential()

    @Test
    fun `parseX509Certificate should parse a DER encoded certificate`() {
        val certificate = parseX509Certificate(verifier.certificate.encoded)

        assertContentEquals(verifier.certificate.encoded, certificate.encoded)
        assertIs<ECPublicKey>(certificate.publicKey)
    }

    @Test
    fun `parseX509Certificate should name an Ed25519 certificate key Ed25519`() {
        val ed25519Verifier = X509HashTestData.createVerifierCredential(keyType = VerifierKeyType.ED25519)

        val certificate = parseX509Certificate(ed25519Verifier.certificate.encoded)

        assertEquals("Ed25519", certificate.publicKey.algorithm)
    }

    @Test
    fun `parseX509Certificate should reject data that is not exactly one DER encoded certificate`() {
        val pemCertificate = "-----BEGIN CERTIFICATE-----\n${verifier.x5cEntry}\n-----END CERTIFICATE-----\n"
        val invalidInputs = listOf(
            "not a certificate".toByteArray(),
            verifier.certificate.encoded + byteArrayOf(0x00),
            pemCertificate.toByteArray(),
        )

        invalidInputs.forEach { input ->
            assertFailsWith<CertificateException> { parseX509Certificate(input) }
        }
    }

    @Test
    fun `validateCertificationPath should accept a chain through an intermediate CA to the root CA`() {
        val intermediateIssuedVerifier = X509HashTestData.createVerifierCredential(
            issuer = X509HashTestData.intermediateCertificateAuthority
        )

        validateCertificationPath(
            listOf(intermediateIssuedVerifier.certificate) + intermediateIssuedVerifier.intermediateCertificates,
            listOf(X509HashTestData.rootCertificateAuthority.certificate)
        )
    }

    @Test
    fun `validateCertificationPath should reject a chain that does not lead to a trust anchor`() {
        val otherCertificateAuthority =
            X509HashTestData.createCertificateAuthority("C=IN,O=Other Trust Services,CN=Other Root CA")

        assertFailsWith<GeneralSecurityException> {
            validateCertificationPath(listOf(verifier.certificate), listOf(otherCertificateAuthority.certificate))
        }
    }

    @Test
    fun `isSelfSigned should be true only for a certificate that verifies with its own key`() {
        assertTrue(X509HashTestData.rootCertificateAuthority.certificate.isSelfSigned())
        assertTrue(X509HashTestData.createSelfSignedVerifierCredential().certificate.isSelfSigned())
        assertFalse(X509HashTestData.intermediateCertificateAuthority.certificate.isSelfSigned())
        assertFalse(verifier.certificate.isSelfSigned())
    }

    @Test
    fun `encodeToBase64UrlWithoutPadding should use the URL-safe alphabet without padding`() {
        // SHA-256 of "abc" in standard base64 is "ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0="
        assertEquals(
            "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0",
            encodeToBase64UrlWithoutPadding(generateHash("abc".toByteArray()))
        )
    }
}
