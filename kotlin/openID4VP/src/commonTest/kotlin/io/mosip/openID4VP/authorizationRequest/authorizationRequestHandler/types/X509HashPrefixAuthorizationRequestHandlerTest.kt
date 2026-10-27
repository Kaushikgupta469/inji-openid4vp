package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import com.fasterxml.jackson.module.kotlin.jacksonObjectMapper
import com.nimbusds.jose.crypto.impl.ECDSA
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.slot
import io.mockk.unmockkAll
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.DCQL_QUERY
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.REQUEST_URI_METHOD
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.ProofType
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.openID4VP.testData.presentationDefinitionMap
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.verifierNonce
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.KeyUsage
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.math.BigInteger
import java.net.URLEncoder
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.ECGenParameterSpec
import java.util.Base64
import java.util.Date
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

private const val DAY_IN_MILLIS = 24 * 60 * 60 * 1000L

class X509HashPrefixAuthorizationRequestHandlerTest {

    private val setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = mockk(relaxed = true)
    private val walletNonce = "qPmxiNFCR3QTm19POc8u"
    private val verifier = X509HashTestData.createVerifierCredential()
    private lateinit var walletConfig: WalletConfig

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers {
            Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg())
        }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { Base64.getUrlDecoder().decode(firstArg<String>()) }

        walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to LdpVpFormatSupported(proofTypeValues = listOf(ProofType.Ed25519Signature2020))
            ),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.X509_HASH),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.ES256, SignatureAlgorithm.EdDSA),
            verifierTrustAnchors = listOf(X509HashTestData.rootCertificateAuthority.x5cEntry)
        )
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should process a valid request passed by value`() {
        val authorizationRequest = createHandler(requestByValue()).handle()

        assertIs<AuthorizationDcqlRequest>(authorizationRequest)
        assertEquals(verifier.clientId, authorizationRequest.clientId)
    }

    @Test
    fun `should process a valid request passed by reference with request_uri_method post`() {
        val requestUriBody = slot<Map<String, String>>()
        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, capture(requestUriBody), any())
        } returns NetworkResponse(
            200,
            signedRequestObject(payload = X509HashTestData.requestObjectPayload(verifier.clientId, walletNonce)),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )
        val parameters = mutableMapOf<String, Any>(
            CLIENT_ID.value to verifier.clientId,
            REQUEST_URI.value to requestUrl,
            REQUEST_URI_METHOD.value to "post"
        )

        val authorizationRequest = createHandler(parameters).handle()

        assertEquals(verifier.clientId, authorizationRequest.clientId)
        assertEquals(walletNonce, requestUriBody.captured["wallet_nonce"])
        val walletMetadata = assertNotNull(requestUriBody.captured["wallet_metadata"])
        assertTrue(walletMetadata.contains("\"client_id_prefixes_supported\":[\"x509_hash\"]"))
        assertTrue(walletMetadata.contains("\"request_object_signing_alg_values_supported\":[\"ES256\",\"EdDSA\"]"))
    }

    @Test
    fun `should process a valid request signed with EdDSA by an Ed25519 leaf certificate`() {
        val ed25519Verifier = X509HashTestData.createVerifierCredential(keyType = VerifierKeyType.ED25519)

        val authorizationRequest = createHandler(
            requestByValue(signedRequestObject(credential = ed25519Verifier, alg = "EdDSA"), ed25519Verifier.clientId)
        ).handle()

        assertEquals(ed25519Verifier.clientId, authorizationRequest.clientId)
    }

    @Test
    fun `should route an x509_hash client_id received in the authorization request URL to this handler`() {
        val authorizationRequestUrl = "openid4vp://authorize?" +
                "client_id=${URLEncoder.encode(verifier.clientId, Charsets.UTF_8.name())}" +
                "&request=${signedRequestObject()}"

        val authorizationRequest = AuthorizationRequest.validateAndCreateAuthorizationRequest(
            authorizationRequestUrl,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        assertEquals(verifier.clientId, authorizationRequest.clientId)
    }

    @Test
    fun `should reject the request when x509_hash is not supported by the wallet`() {
        walletConfig = walletConfig.copy(clientIdPrefixesSupported = listOf(ClientIdPrefix.DECENTRALIZED_IDENTIFIER))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(requestByValue()).handle()
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals("client_id_prefix x509_hash is not supported by wallet", exception.message)
    }

    @Test
    fun `should reject a client_id whose value is not a base64url encoded SHA-256 hash`() {
        val malformedClientIds = listOf(
            "x509_hash:",
            "${verifier.clientId}=",
            "x509_hash:${verifier.certificate.encoded.sha256Hex()}",
        )

        malformedClientIds.forEach { clientId ->
            val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
                createHandler(requestByValue(signedRequestObject(clientId = clientId), clientId)).handle()
            }

            assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
            assertEquals(
                "client_id must be x509_hash:<base64url-encoded SHA-256 hash of the leaf certificate>",
                exception.message
            )
        }
    }

    @Test
    fun `should reject an unsigned request`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(mutableMapOf(CLIENT_ID.value to verifier.clientId)).handle()
        }

        assertEquals("unsigned request is not supported for given client_id_prefix - x509_hash", exception.message)
    }

    @Test
    fun `should reject the request when the typ header is not oauth-authz-req+jwt`() {
        val header = X509HashTestData.requestObjectHeader(verifier) + ("typ" to "JWT")

        assertRequestObjectRejected(
            signedRequestObject(header = header),
            "Invalid typ in JWS header. Expected 'oauth-authz-req+jwt', found 'JWT'"
        )
    }

    @Test
    fun `should reject the request when the signing algorithm is not supported`() {
        val exception = assertFailsWith<OpenID4VPExceptions.VerificationFailure> {
            createHandler(requestByValue(signedRequestObject(alg = "ES384"))).handle()
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertEquals(
            "Request URI response validation failed No enum constant io.mosip.openID4VP.constants.SignatureAlgorithm.ES384",
            exception.message
        )
    }

    @Test
    fun `should reject a request by value signed with ES256 when the wallet allows only EdDSA`() {
        walletConfig = walletConfig.copy(requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA))

        assertRequestObjectRejected(signedRequestObject(), "request_object_signing_alg is not supported by wallet")
    }

    @Test
    fun `should reject a request by value signed with EdDSA when the wallet allows only ES256`() {
        walletConfig = walletConfig.copy(requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.ES256))
        val ed25519Verifier = X509HashTestData.createVerifierCredential(keyType = VerifierKeyType.ED25519)

        assertRequestObjectRejected(
            signedRequestObject(credential = ed25519Verifier, alg = "EdDSA"),
            "request_object_signing_alg is not supported by wallet",
            clientId = ed25519Verifier.clientId
        )
    }

    @Test
    fun `should reject a request by value when the wallet allows no request object signing algorithms`() {
        walletConfig = walletConfig.copy(requestObjectSigningAlgValuesSupported = null)

        assertRequestObjectRejected(signedRequestObject(), "request_object_signing_alg is not supported by wallet")
    }

    @Test
    fun `should reject the request when x5c is missing or empty`() {
        val headerWithoutX5c = X509HashTestData.requestObjectHeader(verifier) - "x5c"
        val headerWithEmptyX5c = X509HashTestData.requestObjectHeader(verifier) + ("x5c" to emptyList<String>())

        listOf(headerWithoutX5c, headerWithEmptyX5c).forEach { header ->
            assertRequestObjectRejected(
                signedRequestObject(header = header),
                "x5c certificate chain is missing in the JWS header"
            )
        }
    }

    @Test
    fun `should reject the request when the client_id is not the hash of the leaf certificate`() {
        val otherVerifier = X509HashTestData.createVerifierCredential()

        assertRequestObjectRejected(
            signedRequestObject(clientId = otherVerifier.clientId),
            "client_id does not match the SHA-256 hash of the leaf certificate in x5c",
            clientId = otherVerifier.clientId
        )
    }

    @Test
    fun `should reject the request when x5c leaf is not a certificate`() {
        val notACertificate = "not a certificate".toByteArray()
        val clientId = "x509_hash:${Base64.getUrlEncoder().withoutPadding().encodeToString(notACertificate.sha256())}"
        val header = X509HashTestData.requestObjectHeader(verifier) +
                ("x5c" to listOf(Base64.getEncoder().encodeToString(notACertificate)))

        assertRequestObjectRejected(
            signedRequestObject(clientId = clientId, header = header),
            "x5c[0] is not a valid DER-encoded X.509 certificate",
            clientId = clientId
        )
    }

    @Test
    fun `should reject the request when x5c leaf is not standard base64`() {
        // "-" is valid only in base64url
        val header = X509HashTestData.requestObjectHeader(verifier) +
                ("x5c" to listOf(verifier.x5cEntry.replaceFirst('M', '-')))

        assertRequestObjectRejected(
            signedRequestObject(header = header),
            "x5c[0] must be a base64-encoded DER X.509 certificate"
        )
    }

    @Test
    fun `should reject the request when it is not signed with the leaf certificate key`() {
        val otherKeyPair = X509HashTestData.generateKeyPair(VerifierKeyType.EC_P256)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(requestByValue(signedRequestObject(signingKey = otherKeyPair.private))).handle()
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT, exception.errorCode)
        assertEquals(
            "Request URI response validation failed - JWS signature verification failed: JWS signature verification failed",
            exception.message
        )
    }

    @Test
    fun `should reject the request when alg does not match the leaf certificate key`() {
        assertRequestObjectRejected(
            signedRequestObject(alg = "EdDSA"),
            "Signing algorithm EdDSA does not match the leaf certificate key"
        )
    }

    @Test
    fun `should reject the request when the leaf certificate has expired`() {
        val expiredVerifier = X509HashTestData.createVerifierCredential(
            notBefore = Date(System.currentTimeMillis() - 10 * DAY_IN_MILLIS),
            notAfter = Date(System.currentTimeMillis() - DAY_IN_MILLIS)
        )

        assertRequestObjectRejected(
            signedRequestObject(credential = expiredVerifier),
            "Leaf certificate in x5c has expired",
            clientId = expiredVerifier.clientId
        )
    }

    @Test
    fun `should reject the request when the leaf certificate is not yet valid`() {
        val notYetValidVerifier = X509HashTestData.createVerifierCredential(
            notBefore = Date(System.currentTimeMillis() + DAY_IN_MILLIS),
            notAfter = Date(System.currentTimeMillis() + 10 * DAY_IN_MILLIS)
        )

        assertRequestObjectRejected(
            signedRequestObject(credential = notYetValidVerifier),
            "Leaf certificate in x5c is not yet valid",
            clientId = notYetValidVerifier.clientId
        )
    }

    @Test
    fun `should accept a leaf certificate issued by an intermediate CA that chains to the trust anchor`() {
        val intermediateIssuedVerifier = X509HashTestData.createVerifierCredential(
            issuer = X509HashTestData.intermediateCertificateAuthority
        )

        val authorizationRequest = createHandler(
            requestByValue(signedRequestObject(credential = intermediateIssuedVerifier), intermediateIssuedVerifier.clientId)
        ).handle()

        assertEquals(2, intermediateIssuedVerifier.x5c.size)
        assertEquals(intermediateIssuedVerifier.clientId, authorizationRequest.clientId)
    }

    @Test
    fun `should accept an intermediate CA configured as the trust anchor`() {
        walletConfig = walletConfig.copy(
            verifierTrustAnchors = listOf(X509HashTestData.intermediateCertificateAuthority.x5cEntry)
        )
        val intermediateIssuedVerifier = X509HashTestData.createVerifierCredential(
            issuer = X509HashTestData.intermediateCertificateAuthority
        )

        val authorizationRequest = createHandler(
            requestByValue(signedRequestObject(credential = intermediateIssuedVerifier), intermediateIssuedVerifier.clientId)
        ).handle()

        assertEquals(intermediateIssuedVerifier.clientId, authorizationRequest.clientId)
    }

    @Test
    fun `should accept a chain that also carries the root CA certificate`() {
        val header = X509HashTestData.requestObjectHeader(verifier) +
                ("x5c" to verifier.x5c + X509HashTestData.rootCertificateAuthority.x5cEntry)

        val authorizationRequest = createHandler(requestByValue(signedRequestObject(header = header))).handle()

        assertEquals(verifier.clientId, authorizationRequest.clientId)
    }

    @Test
    fun `should accept a leaf certificate without a key usage extension`() {
        val verifierWithoutKeyUsage = X509HashTestData.createVerifierCredential(keyUsage = null)

        val authorizationRequest = createHandler(
            requestByValue(signedRequestObject(credential = verifierWithoutKeyUsage), verifierWithoutKeyUsage.clientId)
        ).handle()

        assertEquals(verifierWithoutKeyUsage.clientId, authorizationRequest.clientId)
    }

    @Test
    fun `should reject the request when no trust anchors are configured`() {
        walletConfig = walletConfig.copy(verifierTrustAnchors = emptyList())

        assertRequestObjectRejected(
            signedRequestObject(),
            "No trust anchors are configured to validate the x5c certificate chain"
        )
    }

    @Test
    fun `should reject the request when a configured trust anchor is not a certificate`() {
        walletConfig = walletConfig.copy(
            verifierTrustAnchors = listOf(X509HashTestData.rootCertificateAuthority.x5cEntry, "not a certificate")
        )

        assertRequestObjectRejected(
            signedRequestObject(),
            "verifierTrustAnchors[1] in the wallet configuration is not a base64-encoded DER X.509 certificate"
        )
    }

    @Test
    fun `should reject a leaf certificate issued by a CA that is not a trust anchor`() {
        val untrustedCertificateAuthority =
            X509HashTestData.createCertificateAuthority("C=IN,O=Other Trust Services,CN=Other Root CA")
        val untrustedVerifier = X509HashTestData.createVerifierCredential(issuer = untrustedCertificateAuthority)

        assertRequestObjectRejectedAsUntrusted(signedRequestObject(credential = untrustedVerifier), untrustedVerifier.clientId)
    }

    @Test
    fun `should reject a chain that leaves out the intermediate CA certificate`() {
        val intermediateIssuedVerifier = X509HashTestData.createVerifierCredential(
            issuer = X509HashTestData.intermediateCertificateAuthority
        )
        val header = X509HashTestData.requestObjectHeader(intermediateIssuedVerifier) +
                ("x5c" to listOf(intermediateIssuedVerifier.x5cEntry))

        assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential = intermediateIssuedVerifier, header = header),
            intermediateIssuedVerifier.clientId
        )
    }

    @Test
    fun `should reject a chain whose intermediate CA certificate has expired`() {
        val expiredCertificateAuthority = X509HashTestData.createCertificateAuthority(
            "C=IN,O=Demo Trust Services,CN=Expired Issuing CA",
            issuer = X509HashTestData.rootCertificateAuthority,
            notBefore = Date(System.currentTimeMillis() - 10 * DAY_IN_MILLIS),
            notAfter = Date(System.currentTimeMillis() - DAY_IN_MILLIS)
        )
        val expiredChainVerifier = X509HashTestData.createVerifierCredential(issuer = expiredCertificateAuthority)

        assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential = expiredChainVerifier),
            expiredChainVerifier.clientId
        )
    }

    @Test
    fun `should reject a leaf certificate issued by another Verifier certificate that is not a CA`() {
        val verifierAsIssuer = TestCertificateAuthority(
            verifier.certificate,
            verifier.keyPair,
            issuer = X509HashTestData.rootCertificateAuthority
        )
        val impersonatingVerifier = X509HashTestData.createVerifierCredential(
            subject = "C=IN,O=Other Bank,CN=Other Verifier",
            issuer = verifierAsIssuer
        )

        assertEquals(2, impersonatingVerifier.x5c.size)
        assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential = impersonatingVerifier),
            impersonatingVerifier.clientId
        )
    }

    @Test
    fun `should reject a leaf certificate issued by a configured trust anchor that is not a CA`() {
        val verifierAsIssuer = TestCertificateAuthority(
            verifier.certificate,
            verifier.keyPair,
            issuer = X509HashTestData.rootCertificateAuthority
        )
        val impersonatingVerifier = X509HashTestData.createVerifierCredential(
            subject = "C=IN,O=Other Bank,CN=Other Verifier",
            issuer = verifierAsIssuer
        )
        walletConfig = walletConfig.copy(verifierTrustAnchors = listOf(verifier.x5cEntry))

        assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential = impersonatingVerifier),
            impersonatingVerifier.clientId
        )
    }

    @Test
    fun `should reject a self-signed leaf certificate that is not a trust anchor as untrusted`() {
        val selfSignedVerifier = X509HashTestData.createSelfSignedVerifierCredential()

        assertRequestObjectRejectedAsUntrusted(
            signedRequestObject(credential = selfSignedVerifier),
            selfSignedVerifier.clientId
        )
    }

    @Test
    fun `should reject a self-signed leaf certificate even when it is configured as a trust anchor`() {
        val selfSignedVerifier = X509HashTestData.createSelfSignedVerifierCredential()
        walletConfig = walletConfig.copy(verifierTrustAnchors = listOf(selfSignedVerifier.x5cEntry))

        assertRequestObjectRejected(
            signedRequestObject(credential = selfSignedVerifier),
            "Leaf certificate in x5c must not be self-signed",
            clientId = selfSignedVerifier.clientId
        )
    }

    @Test
    fun `should reject a leaf certificate whose key usage does not allow digitalSignature`() {
        val keyEnciphermentVerifier = X509HashTestData.createVerifierCredential(keyUsage = KeyUsage.keyEncipherment)

        assertRequestObjectRejected(
            signedRequestObject(credential = keyEnciphermentVerifier),
            "Key usage of the leaf certificate in x5c does not allow digitalSignature",
            clientId = keyEnciphermentVerifier.clientId
        )
    }

    @Test
    fun `should reject the request when an intermediate x5c entry is not a certificate`() {
        val header = X509HashTestData.requestObjectHeader(verifier) +
                ("x5c" to listOf(verifier.x5cEntry, Base64.getEncoder().encodeToString("not a certificate".toByteArray())))

        assertRequestObjectRejected(
            signedRequestObject(header = header),
            "x5c[1] is not a valid DER-encoded X.509 certificate"
        )
    }

    @Test
    fun `should reject the request when an intermediate x5c entry is not standard base64`() {
        val header = X509HashTestData.requestObjectHeader(verifier) +
                ("x5c" to listOf(verifier.x5cEntry, "-_not-base64"))

        assertRequestObjectRejected(
            signedRequestObject(header = header),
            "x5c[1] must be a base64-encoded DER X.509 certificate"
        )
    }

    @Test
    fun `should reject the request when the client_id in the request object differs from the one received`() {
        val otherVerifier = X509HashTestData.createVerifierCredential()
        val payload = X509HashTestData.requestObjectPayload(otherVerifier.clientId)

        val exception = assertFailsWith<OpenID4VPExceptions.MismatchingClientIDInRequest> {
            createHandler(requestByValue(signedRequestObject(payload = payload))).handle()
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
    }

    @Test
    fun `should reject a Draft 23 style request with presentation_definition`() {
        val payload = X509HashTestData.requestObjectPayload(verifier.clientId) - DCQL_QUERY.value +
                (PRESENTATION_DEFINITION.value to presentationDefinitionMap)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(requestByValue(signedRequestObject(payload = payload))).handle()
        }

        assertEquals("Spec version identification from request parameters failed", exception.message)
    }

    @Test
    fun `getWalletMetadata should list x509_hash and the supported request object signing algorithms`() {
        val walletMetadata = createHandler(requestByValue()).getWalletMetadata(walletConfig)

        assertEquals(listOf("x509_hash"), walletMetadata["client_id_prefixes_supported"])
        assertEquals(listOf("ES256", "EdDSA"), walletMetadata["request_object_signing_alg_values_supported"])
    }

    @Test
    fun `extractPublicKey should return the public key of the leaf certificate in x5c`() {
        val publicKey = createHandler(requestByValue()).extractPublicKey(
            SignatureAlgorithm.ES256,
            X509HashTestData.requestObjectHeader(verifier)
        )

        assertContentEquals(verifier.certificate.publicKey.encoded, publicKey.encoded)
    }

    private fun createHandler(parameters: MutableMap<String, Any>) =
        X509HashPrefixAuthorizationRequestHandler(
            clientId = parameters[CLIENT_ID.value] as String,
            specVersion = SpecVersion.V1,
            authorizationRequestParameters = parameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

    private fun requestByValue(
        request: String = signedRequestObject(),
        clientId: String = verifier.clientId,
    ): MutableMap<String, Any> = mutableMapOf(
        CLIENT_ID.value to clientId,
        REQUEST.value to request
    )

    private fun signedRequestObject(
        credential: X509VerifierCredential = verifier,
        clientId: String = credential.clientId,
        alg: String = "ES256",
        header: Map<String, Any> = X509HashTestData.requestObjectHeader(credential, alg),
        payload: Map<String, Any> = X509HashTestData.requestObjectPayload(clientId),
        signingKey: PrivateKey = credential.keyPair.private,
    ): String = X509HashTestData.signRequestObject(header, payload, signingKey)

    private fun assertRequestObjectRejected(
        request: String,
        expectedMessage: String,
        clientId: String = verifier.clientId,
    ) {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(requestByValue(request, clientId)).handle()
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT, exception.errorCode)
        assertEquals("Request URI response validation failed - $expectedMessage", exception.message)
    }

    private fun assertRequestObjectRejectedAsUntrusted(request: String, clientId: String) {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(requestByValue(request, clientId)).handle()
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT, exception.errorCode)
        assertTrue(
            exception.message.startsWith("Request URI response validation failed - x5c certificate chain is not trusted: "),
            exception.message
        )
    }

    private fun ByteArray.sha256(): ByteArray = java.security.MessageDigest.getInstance("SHA-256").digest(this)

    private fun ByteArray.sha256Hex(): String = sha256().joinToString("") { "%02x".format(it) }
}

private const val ES256_SIGNATURE_LENGTH = 64

internal enum class VerifierKeyType { EC_P256, ED25519 }

internal fun X509Certificate.toX5cEntry(): String = Base64.getEncoder().encodeToString(encoded)

// Keeps the encoded name, so that it matches the issuer name of the certificates it issues
private fun X509Certificate.subjectName(): X500Name = X500Name.getInstance(subjectX500Principal.encoded)

internal class TestCertificateAuthority(
    val certificate: X509Certificate,
    val keyPair: KeyPair,
    val issuer: TestCertificateAuthority? = null,
) {
    val x5cEntry: String = certificate.toX5cEntry()

    // x5c leaves out the root CA (HAIP 1.0)
    val intermediateCertificates: List<X509Certificate> =
        if (issuer == null) emptyList() else listOf(certificate) + issuer.intermediateCertificates
}

internal class X509VerifierCredential(
    val certificate: X509Certificate,
    val keyPair: KeyPair,
    val intermediateCertificates: List<X509Certificate> = emptyList(),
) {
    val certificateHash: String = Base64.getUrlEncoder().withoutPadding()
        .encodeToString(MessageDigest.getInstance("SHA-256").digest(certificate.encoded))
    val clientId: String = "x509_hash:$certificateHash"
    val x5cEntry: String = certificate.toX5cEntry()
    val x5c: List<String> = listOf(x5cEntry) + intermediateCertificates.map { it.toX5cEntry() }
}

internal object X509HashTestData {
    private val bouncyCastleProvider = BouncyCastleProvider()

    const val REQUEST_OBJECT_TYPE = "oauth-authz-req+jwt"

    // X500Name keeps the given order, so names are written most significant attribute first
    val rootCertificateAuthority = createCertificateAuthority("C=IN,O=Demo Trust Services,CN=Demo Root CA")
    val intermediateCertificateAuthority = createCertificateAuthority(
        "C=IN,O=Demo Trust Services,CN=Demo Issuing CA",
        issuer = rootCertificateAuthority
    )

    fun createCertificateAuthority(
        name: String,
        issuer: TestCertificateAuthority? = null,
        notBefore: Date = Date(System.currentTimeMillis() - DAY_IN_MILLIS),
        notAfter: Date = Date(System.currentTimeMillis() + 3650 * DAY_IN_MILLIS),
    ): TestCertificateAuthority {
        val keyPair = generateKeyPair(VerifierKeyType.EC_P256)
        val certificateBuilder = certificateBuilder(
            issuerName = issuer?.certificate?.subjectName() ?: X500Name(name),
            subjectName = X500Name(name),
            publicKey = keyPair.public,
            notBefore = notBefore,
            notAfter = notAfter
        )
            .addExtension(Extension.basicConstraints, true, BasicConstraints(true))
            .addExtension(Extension.keyUsage, true, KeyUsage(KeyUsage.keyCertSign or KeyUsage.cRLSign))
        val certificate = buildCertificate(certificateBuilder, signingKey = (issuer?.keyPair ?: keyPair).private)
        return TestCertificateAuthority(certificate, keyPair, issuer)
    }

    // keyUsage null leaves the key usage extension out
    fun createVerifierCredential(
        keyType: VerifierKeyType = VerifierKeyType.EC_P256,
        subject: String = "C=IN,O=Demo Bank,CN=Demo Verifier",
        notBefore: Date = Date(System.currentTimeMillis() - DAY_IN_MILLIS),
        notAfter: Date = Date(System.currentTimeMillis() + 365 * DAY_IN_MILLIS),
        issuer: TestCertificateAuthority = rootCertificateAuthority,
        keyUsage: Int? = KeyUsage.digitalSignature,
    ): X509VerifierCredential {
        val keyPair = generateKeyPair(keyType)
        val certificateBuilder = verifierCertificateBuilder(
            issuerName = issuer.certificate.subjectName(),
            subject = subject,
            publicKey = keyPair.public,
            notBefore = notBefore,
            notAfter = notAfter,
            keyUsage = keyUsage
        )
        val certificate = buildCertificate(certificateBuilder, signingKey = issuer.keyPair.private)
        return X509VerifierCredential(certificate, keyPair, issuer.intermediateCertificates)
    }

    fun createSelfSignedVerifierCredential(
        subject: String = "C=IN,O=Demo Bank,CN=Demo Verifier",
    ): X509VerifierCredential {
        val keyPair = generateKeyPair(VerifierKeyType.EC_P256)
        val certificateBuilder = verifierCertificateBuilder(
            issuerName = X500Name(subject),
            subject = subject,
            publicKey = keyPair.public,
            notBefore = Date(System.currentTimeMillis() - DAY_IN_MILLIS),
            notAfter = Date(System.currentTimeMillis() + 365 * DAY_IN_MILLIS),
            keyUsage = KeyUsage.digitalSignature
        )
        return X509VerifierCredential(buildCertificate(certificateBuilder, signingKey = keyPair.private), keyPair)
    }

    fun requestObjectHeader(
        credential: X509VerifierCredential,
        alg: String = "ES256",
    ): Map<String, Any> = mapOf(
        "typ" to REQUEST_OBJECT_TYPE,
        "alg" to alg,
        "x5c" to credential.x5c
    )

    fun requestObjectPayload(
        clientId: String,
        walletNonce: String? = null,
    ): Map<String, Any> = buildMap {
        put("client_id", clientId)
        put("response_type", "vp_token")
        put("response_mode", "direct_post")
        put("response_uri", responseUrl)
        put("nonce", verifierNonce)
        put("state", "+mRQe1d6pBoJqF6Ab28klg==")
        put(
            "dcql_query", mapOf(
                "credentials" to listOf(
                    mapOf(
                        "id" to "identity_credential",
                        "format" to "ldp_vc",
                        "meta" to emptyMap<String, Any>()
                    )
                )
            )
        )
        walletNonce?.let { put("wallet_nonce", it) }
    }

    // Signs by key type, whatever alg the header declares
    fun signRequestObject(
        header: Map<String, Any>,
        payload: Map<String, Any>,
        signingKey: PrivateKey,
    ): String {
        val mapper = jacksonObjectMapper()
        val encodedHeader = base64Url(mapper.writeValueAsBytes(header))
        val encodedPayload = base64Url(mapper.writeValueAsBytes(payload))
        val signingInput = "$encodedHeader.$encodedPayload".toByteArray(Charsets.UTF_8)
        return "$encodedHeader.$encodedPayload.${base64Url(sign(signingInput, signingKey))}"
    }

    fun generateKeyPair(keyType: VerifierKeyType): KeyPair {
        return when (keyType) {
            VerifierKeyType.EC_P256 -> KeyPairGenerator.getInstance("EC", bouncyCastleProvider)
                .apply { initialize(ECGenParameterSpec("secp256r1")) }
                .generateKeyPair()

            VerifierKeyType.ED25519 -> KeyPairGenerator.getInstance("Ed25519", bouncyCastleProvider)
                .generateKeyPair()
        }
    }

    private fun verifierCertificateBuilder(
        issuerName: X500Name,
        subject: String,
        publicKey: PublicKey,
        notBefore: Date,
        notAfter: Date,
        keyUsage: Int?,
    ): X509v3CertificateBuilder {
        val certificateBuilder = certificateBuilder(issuerName, X500Name(subject), publicKey, notBefore, notAfter)
            .addExtension(Extension.basicConstraints, true, BasicConstraints(false))
        keyUsage?.let { certificateBuilder.addExtension(Extension.keyUsage, true, KeyUsage(it)) }
        return certificateBuilder
    }

    private fun certificateBuilder(
        issuerName: X500Name,
        subjectName: X500Name,
        publicKey: PublicKey,
        notBefore: Date,
        notAfter: Date,
    ): X509v3CertificateBuilder = JcaX509v3CertificateBuilder(
        issuerName,
        BigInteger.valueOf(System.nanoTime()),
        notBefore,
        notAfter,
        subjectName,
        publicKey
    )

    private fun buildCertificate(certificateBuilder: X509v3CertificateBuilder, signingKey: PrivateKey): X509Certificate {
        val contentSigner = JcaContentSignerBuilder("SHA256withECDSA")
            .setProvider(bouncyCastleProvider)
            .build(signingKey)
        return JcaX509CertificateConverter()
            .setProvider(bouncyCastleProvider)
            .getCertificate(certificateBuilder.build(contentSigner))
    }

    private fun sign(signingInput: ByteArray, signingKey: PrivateKey): ByteArray {
        return if (signingKey.algorithm == "EC" || signingKey.algorithm == "ECDSA") {
            val derSignature = Signature.getInstance("SHA256withECDSA", bouncyCastleProvider).run {
                initSign(signingKey)
                update(signingInput)
                sign()
            }
            // JWS carries ECDSA signatures as R || S
            ECDSA.transcodeSignatureToConcat(derSignature, ES256_SIGNATURE_LENGTH)
        } else {
            Signature.getInstance("Ed25519", bouncyCastleProvider).run {
                initSign(signingKey)
                update(signingInput)
                sign()
            }
        }
    }

    private fun base64Url(data: ByteArray): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(data)
}
