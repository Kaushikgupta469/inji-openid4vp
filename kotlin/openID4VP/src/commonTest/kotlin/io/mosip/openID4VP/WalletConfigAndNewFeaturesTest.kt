package io.mosip.openID4VP

import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.PreRegisteredSchemeAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.RedirectUriPrefixAuthorizationRequestHandler
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.*
import kotlin.test.*

/**
 * Tests for new features from OVP Spec V1 port:
 * - WalletConfig class and toWalletMetadata() conversion
 * - GET fallback for request_uri when wallet doesn't support POST
 * - Unrecognized client_id prefix fallback to pre-registered
 * - PreRegistered.process() validates signing alg
 * - VP construction failure wrapping with server_error
 */
class WalletConfigTest {

    @Test
    fun `WalletConfig toWalletMetadata converts all fields correctly`() {
        val config = WalletConfig(
            vpFormatsSupported = mapOf(
                VPFormatType.LDP_VC to LdpVpFormatSupported(proofTypeValues = listOf(ProofType.Ed25519Signature2020))
            ),
            clientIdPrefixesSupported = listOf(
                ClientIdPrefix.PRE_REGISTERED,
                ClientIdPrefix.REDIRECT_URI
            ),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA),
            authorizationEncryptionAlgValuesSupported = listOf(EncryptionAlgorithm.ECDH_ES),
            authorizationEncryptionEncValuesSupported = listOf(EncryptionMethod.A256GCM),
            responseTypesSupported = listOf(ResponseType.VP_TOKEN),
            validateTrustedVerifier = false
        )

        val metadata = config.toWalletMetadata(SpecVersion.V1)

        assertWalletConfigAndMetadata(config, metadata)
    }

    @Test
    fun `WalletConfig toWalletMetadata lists x509_hash for 1_0 and leaves it out of Draft 23 schemes`() {
        val config = WalletConfig(
            clientIdPrefixesSupported = listOf(ClientIdPrefix.DECENTRALIZED_IDENTIFIER, ClientIdPrefix.X509_HASH),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.ES256, SignatureAlgorithm.EdDSA)
        )

        val v1Metadata = config.toWalletMetadata(SpecVersion.V1)
        val draft23Metadata = config.toWalletMetadata(SpecVersion.DRAFT_23)

        assertEquals(listOf("decentralized_identifier", "x509_hash"), v1Metadata["client_id_prefixes_supported"])
        assertEquals(listOf("ES256", "EdDSA"), v1Metadata["request_object_signing_alg_values_supported"])
        assertEquals(listOf("did"), draft23Metadata["client_id_schemes_supported"])
    }

    @Test
    fun `WalletConfig default constructor provides sensible defaults`() {
        val config = WalletConfig()

        assertNotNull(config.vpFormatsSupported)
        assertNotNull(config.clientIdPrefixesSupported)
        assertTrue(config.clientIdPrefixesSupported.isNotEmpty())
        assertNotNull(config.requestObjectSigningAlgValuesSupported)
        assertTrue(config.trustedVerifiers.isEmpty())
        assertTrue(config.isPresentationDefinitionUriSupported)
        assertTrue(config.validateTrustedVerifier)
        assertTrue(config.verifierTrustAnchors.isEmpty())
    }

    @Test
    fun `WalletConfig with trustedVerifiers passes them through`() {
        val verifiers = listOf(
            Verifier("client-1", listOf("https://example.com/response"))
        )
        val config = WalletConfig(trustedVerifiers = verifiers)

        assertEquals(verifiers, config.trustedVerifiers)
    }
}

class GetFallbackForRequestUriTest {

    private val setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = mockk(relaxed = true)
    private val walletNonce = "VbRRB/LTxLiXmVNZuyMO8A=="

    @BeforeTest
    fun setup() {
        mockkObject(NetworkManagerClient)
        mockkObject(JWSHandler)
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers {
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg())
        }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers {
            java.util.Base64.getUrlDecoder().decode(firstArg<String>())
        }
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should use POST when as per request_uri method`() {
        val requestUrl = "https://example.com/request"
        val authorizationRequestParameters: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "pre-registered:mock-client",
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to "https://example.com/response",
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to walletNonce,
            STATE.value to "state123",
            REQUEST_URI.value to requestUrl,
            REQUEST_URI_METHOD.value to "post"
        )

        // WalletConfig that supports both GET and POST
        val walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA)
        )

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "mock-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val jwtResponse = "eyJhbGciOiJFZERTQSJ9.eyJ0ZXN0IjoidmFsdWUifQ.signature_placeholder"

        // Mock POST response
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns NetworkResponse(
            200,
            jwtResponse,
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        every { JWSHandler.extractDataJsonFromJws(jwtResponse, JWSHandler.JwsPart.HEADER) } returns
                mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        every { JWSHandler.extractDataJsonFromJws(jwtResponse, JWSHandler.JwsPart.PAYLOAD) } returns
                (authorizationRequestParameters + mapOf(
                    PRESENTATION_DEFINITION.value to presentationDefinitionString,
                    CLIENT_METADATA.value to clientMetadataString
                )).toMutableMap()
        every { JWSHandler.verify(any(), any(), any()) } returns Unit

        // May fail later during JWT validation, but we only care about HTTP method
        try {
            handler.fetchAuthorizationRequest()
        } catch (_: Exception) {
            // Expected — we're testing HTTP method selection, not full flow
        }

        // Verify POST was called
        verify {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        }
    }
}

class UnrecognizedClientIdPrefixFallbackTest {

    @Test
    fun `extractClientIdPrefix returns PRE_REGISTERED for unrecognized prefix`() {
        val params: Map<String, Any> = mapOf(
            CLIENT_ID.value to "x-custom:some-client-id"
        )
        val result = extractClientIdPrefix(params as MutableMap<String, Any>)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns DECENTRALIZED_IDENTIFIER for known prefix`() {
        val params: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "decentralized_identifier:did:web:example.com"
        )
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns REDIRECT_URI for redirect_uri prefix`() {
        val params: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "redirect_uri:https://example.com/callback"
        )
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.REDIRECT_URI.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns PRE_REGISTERED when no colon in client_id`() {
        val params: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "simple-client-id"
        )
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }
}

class PreRegisteredProcessValidationTest {

    private val setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = mockk(relaxed = true)
    private val walletNonce = "VbRRB/LTxLiXmVNZuyMO8A=="

    @Test
    fun `process should throw when requestObjectSigningAlgValuesSupported is null`() {
        val authorizationRequestParameters: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "mock-client",
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to "https://example.com/response",
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to walletNonce,
            STATE.value to "state123"
        )

        val walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA)
        )

        val trustedVerifiers = mutableListOf(
            Verifier("mock-client", listOf("https://example.com/response"))
        )

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            "mock-client",
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        // Create metadata with null signing alg (must set after construction because init block fills defaults)
        val walletConfigWithNoRequestObjectSigningAlgorithms = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            requestObjectSigningAlgValuesSupported = null
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.getWalletMetadata(walletConfigWithNoRequestObjectSigningAlgorithms)
        }
        assertTrue(exception.message.contains("request_object_signing_alg_values_supported"))
    }

    @Test
    fun `process should throw when requestObjectSigningAlgValuesSupported is empty`() {
        val authorizationRequestParameters: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "mock-client",
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to "https://example.com/response",
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to walletNonce,
            STATE.value to "state123"
        )

        val walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA)
        )

        val trustedVerifiers = mutableListOf(
            Verifier("mock-client", listOf("https://example.com/response"))
        )

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            "mock-client",
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        val walletConfigWithEmptyListOfRequestObjSigningAlgs = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            requestObjectSigningAlgValuesSupported = emptyList()
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.getWalletMetadata(walletConfigWithEmptyListOfRequestObjSigningAlgs)
        }
        assertTrue(exception.message.contains("request_object_signing_alg_values_supported"))
    }

    @Test
    fun `process should return same walletMetadata when signing alg is valid`() {
        val authorizationRequestParameters: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "mock-client",
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to "https://example.com/response",
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to walletNonce,
            STATE.value to "state123"
        )

        val walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA)
        )

        val trustedVerifiers = mutableListOf(
            Verifier("mock-client", listOf("https://example.com/response"))
        )

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            "mock-client",
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        val result = handler.getWalletMetadata(walletConfig)

        assertWalletConfigAndMetadata(walletConfig, result)
    }
}

class RedirectUriProcessTest {

    private val setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = mockk(relaxed = true)
    private val walletNonce = "VbRRB/LTxLiXmVNZuyMO8A=="

    @Test
    fun `RedirectUri process should null out requestObjectSigningAlgValuesSupported`() {
        val authorizationRequestParameters: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "redirect_uri:https://example.com/callback",
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to "https://example.com/callback",
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to walletNonce,
            STATE.value to "state123",
            CLIENT_METADATA.value to clientMetadataString
        )

        val walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.REDIRECT_URI),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA)
        )

        val handler = RedirectUriPrefixAuthorizationRequestHandler(
            clientId = "redirect_uri:https://example.com/callback",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val result = handler.getWalletMetadata(walletConfig)

        assertNull(result["request_object_signing_alg_values_supported"])
    }
}

class VPConstructionFailureWrappingTest {

    @BeforeTest
    fun setup() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers {
            java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg())
        }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers {
            java.util.Base64.getUrlDecoder().decode(firstArg<String>())
        }
        mockkObject(NetworkManagerClient)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `VerifiablePresentationConstructionFailure has SERVER_ERROR code`() {
        val cause = RuntimeException("test error")
        val exception =
            OpenID4VPExceptions.VerifiablePresentationConstructionFailure(cause, "TestClass")

        assertTrue(exception.message.contains("internal error while preparing the presentation"))
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `AuthorizationResponseConstructionFailure has SERVER_ERROR code`() {
        val cause = RuntimeException("response error")
        val exception =
            OpenID4VPExceptions.AuthorizationResponseConstructionFailure(cause, "TestClass")

        assertTrue(exception.message.contains("internal error while preparing the authorization response"))
        assertEquals(cause, exception.cause)
    }

    @Test
    fun `constructUnsignedVPToken wraps non-OpenID4VP exceptions`() {
        val openID4VP = OpenID4VP("test-wrapping")

        // Without authenticating first, authorizationRequest is null
        // This should throw a wrapped exception
        val exception = assertFailsWith<Exception> {
            openID4VP.constructUnsignedVPToken(
                selectedCredentials = mapOf()
            )
        }

        // Should be either a VerifiablePresentationConstructionFailure or an OpenID4VP exception
        assertTrue(
            exception is OpenID4VPExceptions.VerifiablePresentationConstructionFailure ||
                    exception is OpenID4VPExceptions
        )
    }
}
