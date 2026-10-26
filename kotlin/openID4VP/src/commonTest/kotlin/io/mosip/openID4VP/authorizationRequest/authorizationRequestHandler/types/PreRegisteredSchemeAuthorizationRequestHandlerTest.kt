package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.Verifier
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.resolveJwksFromUri
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.*
import io.mosip.openID4VP.testData.JWSUtil.Companion.buildTestJwk
import io.mosip.openID4VP.testData.JWSUtil.Companion.generateP256PublicKey
import io.mosip.openID4VP.testData.JWSUtil.Companion.toP256Jwk
import org.junit.jupiter.api.Test
import java.security.interfaces.ECPublicKey
import kotlin.test.*

class PreRegisteredSchemeAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletConfig: WalletConfig
    private val setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = mockk(relaxed = true)
    private val validClientId = "mock-client"
    private var trustedVerifiers: MutableList<Verifier> = mutableListOf(
        Verifier(
            "mock-client", listOf(
                "https://mock-verifier.com/response-uri", "https://verifier.env2.com/responseUri"
            )
        ),
        Verifier(
            clientId = "test-client",
            responseUris = listOf("https://example.com/callback"),
            jwksUri = "https://example.com/.well-known/jwks.json",
            allowUnsignedRequest = false
        )
    )
    private val jwksUri = "https://example.com/.well-known/jwks.json"

    @BeforeTest
    fun setup() {

        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to validClientId,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to responseUrl,
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
        )

        walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
            trustedVerifiers = trustedVerifiers
        )

        mockkStatic("io.mosip.openID4VP.common.UtilsKt")
    }

    @Test
    fun `validateClientId should pass when client ID is trusted and validation is enabled`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        try {
            handler.validateClientId()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateClientId should skip validation when validatePreRegisteredVerifier is false`() {
        authorizationRequestParameters[CLIENT_ID.value] = "untrusted-client-id"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            "untrusted-client-id",
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig = WalletConfig(
                vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
                clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
                trustedVerifiers = trustedVerifiers,
                validateTrustedVerifier = false
            ),
            setResponseDispatchInfo,
            walletNonce
        )

        try {
            handler.validateClientId()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateClientId should throw exception when client ID is not trusted`() {
        authorizationRequestParameters[CLIENT_ID.value] = "untrusted-client-id"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            "untrusted-client-id",
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        val exception = assertFailsWith<Exception> {
            handler.validateClientId()
        }
        assertTrue(exception.message?.contains("Verifier is not trusted") == true)
    }

    @Test
    fun `process should validate and return wallet metadata with requestObjectSigningAlgValuesSupported preserved`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        val processedMetadata = handler.getWalletMetadata(walletConfig)

        assertEquals(
            listOf(SignatureAlgorithm.EdDSA.value),
            processedMetadata["request_object_signing_alg_values_supported"]
        )
    }


    @Test
    fun `validateAndParseRequestFields should pass for trusted client with valid response URI`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        try {
            handler.validateAndParseRequestFields()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    @Test
    fun `validateAndParseRequestFields should not throw exception when client metadata of the pre-registered verifier is not known and its available in authorization request`() {
        val trustedVerifiersWithoutClientMetadata: List<Verifier> = listOf(
            Verifier(
                "mock-client",
                listOf(
                    "https://mock-verifier.com/response-uri",
                    "https://verifier.env2.com/responseUri"
                ),
            )
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            (authorizationRequestParameters + mapOf(
                CLIENT_METADATA.value to clientMetadataString
            )) as MutableMap<String, Any>,
            WalletConfig(trustedVerifiers = trustedVerifiersWithoutClientMetadata),
            setResponseDispatchInfo,
            walletNonce
        )

        assertDoesNotThrow {
            handler.validateAndParseRequestFields()
        }
    }

    @Test
    fun `setResponseUrl should reject both response_uri and redirect_uri for direct_post`() {
        authorizationRequestParameters[REDIRECT_URI.value] = "https://example.com/redirect"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.prepareDispatchInfo()
        }
        assertOpenId4VPException(exception,"redirect_uri should not be present for given response_mode", OpenID4VPErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `setResponseUrl should reject both response_uri and redirect_uri for direct_post_jwt`() {
        authorizationRequestParameters[RESPONSE_MODE.value] = "direct_post.jwt"
        authorizationRequestParameters[REDIRECT_URI.value] = "https://example.com/redirect"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.prepareDispatchInfo()
        }
        assertOpenId4VPException(exception,"redirect_uri should not be present for given response_mode", OpenID4VPErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `validateClientAuthenticity should throw exception when response URI is not trusted`() {
        authorizationRequestParameters[RESPONSE_URI.value] =
            "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions> {
            handler.validateClientAuthenticity()
        }
        assertOpenId4VPException(exception,"Verifier is not trusted by the wallet", OpenID4VPErrorCodes.INVALID_CLIENT)
    }

    @Test
    fun `validateClientAuthenticity should throw missing input when response_uri is absent`() {
        authorizationRequestParameters.remove(RESPONSE_URI.value)
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.validateClientAuthenticity()
        }
        assertOpenId4VPException(exception,"Missing Input: response_uri param is required", OpenID4VPErrorCodes.INVALID_REQUEST)
    }

    @Test
    fun `validateClientAuthenticity should skip validation when validateTrustedVerifier is false`() {
        authorizationRequestParameters[RESPONSE_URI.value] =
            "https://untrusted.verifier.com/response"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig = WalletConfig(
                vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
                clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
                trustedVerifiers = trustedVerifiers,
                validateTrustedVerifier = false
            ),
            setResponseDispatchInfo,
            walletNonce
        )

        try {
            handler.validateClientAuthenticity()
        } catch (e: Throwable) {
            fail("Expected no exception, but got: ${e.message}")
        }
    }

    private fun handlerFor(clientId: String) = PreRegisteredSchemeAuthorizationRequestHandler(
        clientId = clientId,
        specVersion = SpecVersion.DRAFT_23,
        authorizationRequestParameters = authorizationRequestParameters,
        walletConfig = walletConfig,
        setResponseDispatchInfo = setResponseDispatchInfo,
        walletNonce = walletNonce
    )

    @Test
    fun `should extract the P-256 key for ES256 when kid is present`() {
        val p256PublicKey = generateP256PublicKey()
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(p256PublicKey.toP256Jwk(kid = "ec-kid")))

        val publicKey = handlerFor("test-client").extractPublicKey(SignatureAlgorithm.ES256, mapOf("kid" to "ec-kid"))

        assertIs<ECPublicKey>(publicKey)
        assertEquals(p256PublicKey.w, publicKey.w)
    }

    @Test
    fun `should select the key by the signing algorithm when kid is absent`() {
        val p256PublicKey = generateP256PublicKey()
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(buildTestJwk(kid = "ed-kid"), p256PublicKey.toP256Jwk(kid = "ec-kid")))
        val handler = handlerFor("test-client")

        val es256Key = handler.extractPublicKey(SignatureAlgorithm.ES256, emptyMap())
        val eddsaKey = handler.extractPublicKey(SignatureAlgorithm.EdDSA, emptyMap())

        assertIs<ECPublicKey>(es256Key)
        assertEquals(p256PublicKey.w, es256Key.w)
        assertFalse(eddsaKey is ECPublicKey)
    }

    @Test
    fun `should throw error when no key in the jwks supports the signing algorithm`() {
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(buildTestJwk(kid = "ed-kid")))

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handlerFor("test-client").extractPublicKey(SignatureAlgorithm.ES256, emptyMap())
        }

        assertTrue(ex.message.contains("No public key found for algorithm: ES256 with signature usage"))
    }

    @Test
    fun `should throw error when an EC key has no y coordinate`() {
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        val withoutY = generateP256PublicKey().toP256Jwk(kid = "ec-kid").copy(y = null)
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(withoutY))

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handlerFor("test-client").extractPublicKey(SignatureAlgorithm.ES256, mapOf("kid" to "ec-kid"))
        }

        assertTrue(ex.message.contains("y is required for an EC key"))
    }

    @Test
    fun `should throw error when an EC key is not a point on the P-256 curve`() {
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        val validJwk = generateP256PublicKey().toP256Jwk(kid = null)
        val notOnCurve = validJwk.copy(y = generateP256PublicKey().toP256Jwk().y)
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(notOnCurve))

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handlerFor("test-client").extractPublicKey(SignatureAlgorithm.ES256, emptyMap())
        }

        assertTrue(ex.message.contains("Public key extraction failed"))
    }

    @Test
    fun `should throw error when an EC key is on an unsupported curve`() {
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        val p384Jwk = buildTestJwk(kid = "ec-kid", alg = "ES384", kty = "EC", crv = "P-384", y = "AAAA")
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(p384Jwk))

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handlerFor("test-client").extractPublicKey(SignatureAlgorithm.ES256, mapOf("kid" to "ec-kid"))
        }

        assertTrue(ex.message.contains("Public key extraction failed - Curve - P-384 is not supported. Supported: P-256"))
    }

    @Test
    fun `should extract key successfully when kid is present`() {
        val testKid = "test-key"
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(jwkList)

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val publicKey = handler.extractPublicKey(SignatureAlgorithm.EdDSA, mapOf("kid" to testKid))

        assertNotNull(publicKey)
        assertEquals("Ed25519", publicKey.algorithm)
        assertTrue(publicKey.encoded.isNotEmpty())
    }


    @Test
    fun `should throw when kid is present and not found in client metadata`() {
        val testKid = "some-other-key"
        val testJwk = buildTestJwk(kid = testKid)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(testJwk))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, mapOf("kid" to "non-existent"))
        }

        assertTrue(ex.message.contains("Public key extraction failed for kid"))
    }

    @Test
    fun `should throw error when no jwks_uri available in the trusted verifier`() {
        authorizationRequestParameters[CLIENT_ID.value] = "mock-client" // this client does not have jwks_uri as per trustedVerifiers

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "mock-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, emptyMap())
        }

        assertTrue(ex.message.contains("Public key extraction failed - Public key information not available in pre-registered data to verify the signed Authorization Request"))
    }

    @Test
    fun `should pick key by alg if no kid and one matching key present`() {
        val testJwk: Jwk = buildTestJwk(kid = null)
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(testJwk))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val publicKey = handler.extractPublicKey(SignatureAlgorithm.EdDSA, emptyMap())
        assertNotNull(publicKey)
    }

    @Test
    fun `should throw if multiple sig-use keys present and no kid`() {
        val key1 = buildTestJwk(kid = "k1")
        val key2 = buildTestJwk(kid = "k2")
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(key1, key2))


        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, emptyMap())
        }

        assertTrue(ex.message.contains("Multiple ambiguous keys found for EdDSA with signature usage"))
    }

    @Test
    fun `should throw if no matching keys for alg`() {
        val key = buildTestJwk(kty = "RSA", crv = "") // non-EdDSA key
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(any(), any()) } returns Jwks(listOf(key))


        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, emptyMap())
        }

        assertTrue(ex.message.contains("No public key found for algorithm: EdDSA with signature usage"))
    }

    @Test
    fun `should throw if curve is unsupported in matching key`() {
        val unsupportedCurveJWK = buildTestJwk(crv = "XYZ")
        authorizationRequestParameters[CLIENT_ID.value] = "test-client"
        every { resolveJwksFromUri(jwksUri, any()) } returns Jwks(listOf(unsupportedCurveJWK))

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = WalletConfig(trustedVerifiers = trustedVerifiers),
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val ex = assertFailsWith<OpenID4VPExceptions.PublicKeyResolutionFailed> {
            handler.extractPublicKey(SignatureAlgorithm.EdDSA, mapOf("kid" to "test-kid"))
        }
        assertTrue(ex.message.contains("Public key extraction failed - Curve - XYZ is not supported. Supported: Ed25519"))
    }

    @Test
    fun `isRequestObjectSupported should return boolean value for trusted client with valid response URI`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig,
            setResponseDispatchInfo,
            walletNonce
        )

        assertFalse(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should return false when validatePreRegisteredVerifier is false`() {
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            validClientId,
            SpecVersion.DRAFT_23,
            authorizationRequestParameters,
            walletConfig = WalletConfig(
                vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported()),
                clientIdPrefixesSupported = listOf(ClientIdPrefix.PRE_REGISTERED),
                trustedVerifiers = trustedVerifiers,
                validateTrustedVerifier = false
            ),
            setResponseDispatchInfo,
            walletNonce
        )
        assertTrue(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should throw when client id not in trusted verifiers`() {
        authorizationRequestParameters[CLIENT_ID.value] = "unknown-client"
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "unknown-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )
        val ex = assertFailsWith<OpenID4VPExceptions.InvalidVerifier> {
            handler.isUnsignedRequestSupported()
        }
        assertTrue(ex.message!!.contains("Verifier is not trusted by the wallet"))
    }

    @Test
    fun `isRequestObjectSupported should return false when verifier does not allow unsigned request`() {
        val verifier = Verifier(
            clientId = "test-client",
            jwksUri = jwksUri,
            allowUnsignedRequest = false,
            responseUris = listOf("https://example.com/response")
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters.apply { put(CLIENT_ID.value, "test-client") },
            walletConfig = WalletConfig(trustedVerifiers = listOf(verifier)),
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )
        assertFalse(handler.isUnsignedRequestSupported())
    }

    @Test
    fun `isRequestObjectSupported should return true when verifier allows unsigned request`() {
        val verifier = Verifier(
            clientId = "test-client",
            jwksUri = jwksUri,
            allowUnsignedRequest = true,
            responseUris = listOf("https://example.com/response")
        )
        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "test-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = authorizationRequestParameters.apply { put(CLIENT_ID.value, "test-client") },
            walletConfig = WalletConfig(trustedVerifiers = listOf(verifier)),
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )
        assertTrue(handler.isUnsignedRequestSupported())
    }
}
