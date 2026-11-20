package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo

import io.mockk.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.parseAndValidatePresentationDefinition
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ProofType
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertDoesNotThrow
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.openID4VP.testData.clientMetadataString
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.responseUrl
import org.junit.jupiter.api.Test
import kotlin.test.*

class RedirectUriPrefixAuthorizationRequestHandlerTest {

    private lateinit var authorizationRequestParameters: MutableMap<String, Any>
    private lateinit var walletConfig: WalletConfig
    private val setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = mockk(relaxed = true)
    val walletNonce = "VbRRB/LTxLiXmVNZuyMO8A=="

    @BeforeTest
    fun setup() {

        authorizationRequestParameters = mutableMapOf(
            CLIENT_ID.value to "redirect_uri:$responseUrl",
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_URI.value to responseUrl,
            PRESENTATION_DEFINITION.value to presentationDefinitionString,
            RESPONSE_MODE.value to "direct_post",
            NONCE.value to "VbRRB/LTxLiXmVNZuyMO8A==",
            STATE.value to "+mRQe1d6pBoJqF6Ab28klg==",
            CLIENT_METADATA.value to clientMetadataString
        )

        walletConfig = WalletConfig(
            vpFormatsSupported = mapOf(VPFormatType.LDP_VC to LdpVpFormatSupported(proofTypeValues = listOf(ProofType.Ed25519Signature2020))),
            clientIdPrefixesSupported = listOf(ClientIdPrefix.REDIRECT_URI),
            requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA)
        )
    }

    private fun createHandler(
        params: MutableMap<String, Any> = authorizationRequestParameters,
        specVersion: SpecVersion = SpecVersion.DRAFT_23
    ) =
        RedirectUriPrefixAuthorizationRequestHandler(
            clientId = params[CLIENT_ID.value] as String,
            specVersion = specVersion,
            authorizationRequestParameters = params,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

    private fun createV1DcqlParams(
        responseMode: String,
        requireHolderBinding: Boolean,
        includeState: Boolean
    ): MutableMap<String, Any> {
        return authorizationRequestParameters.toMutableMap().apply {
            remove(PRESENTATION_DEFINITION.value)
            remove(CLIENT_METADATA.value)
            if (!includeState) {
                remove(STATE.value)
            }
            put(RESPONSE_MODE.value, responseMode)
            put(
                DCQL_QUERY.value,
                mapOf(
                    "credentials" to listOf(
                        mapOf(
                            "id" to "identity_credential",
                            "format" to "ldp_vc",
                            "meta" to emptyMap<String, Any>(),
                            "require_cryptographic_holder_binding" to requireHolderBinding
                        )
                    )
                )
            )
            if (responseMode.endsWith(".jwt")) {
                put(
                    CLIENT_METADATA.value,
                    mapOf(
                        "vp_formats_supported" to mapOf(
                            "ldp_vc" to mapOf(
                                "proof_type_values" to listOf("Ed25519Signature2020")
                            )
                        ),
                        "encrypted_response_enc_values_supported" to listOf("A256GCM"),
                        "jwks" to mapOf(
                            "keys" to listOf(
                                mapOf(
                                    "kty" to "OKP",
                                    "crv" to "X25519",
                                    "x" to "BVNVdqorpxCCnTOkkw8S2NAYXvfEvkC-8RDObhrAUA4",
                                    "alg" to "ECDH-ES",
                                    "kid" to "enc-key"
                                )
                            )
                        )
                    )
                )
            }
        }
    }

    @Test
    fun `process should return wallet metadata with requestObjectSigningAlgValuesSupported set to null`() {
        val handler = createHandler()
        val result = handler.getWalletMetadata(walletConfig)
        assertNull(result["request_object_signing_alg_values_supported"])
    }

    @Test
    fun `validateAndParseRequestFields should succeed with valid direct_post response mode`() {
        val handler = createHandler()
        assertDoesNotThrow { handler.validateAndParseRequestFields() }
    }

    @Test
    fun `validateAndParseRequestFields should allow v1 direct_post without state when holder binding is required`() {
        val modifiedParams = createV1DcqlParams("direct_post", requireHolderBinding = true, includeState = false)

        assertDoesNotThrow {
            createHandler(modifiedParams, SpecVersion.V1).validateAndParseRequestFields()
        }
    }

    @Test
    fun `validateAndParseRequestFields should require state when v1 dcql disables holder binding`() {
        val modifiedParams = createV1DcqlParams("direct_post", requireHolderBinding = false, includeState = false)

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            createHandler(modifiedParams, SpecVersion.V1).validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("state") == true)
    }

    @Test
    fun `validateAndParseRequestFields should allow v1 jwt response modes without state when holder binding is required`() {
        listOf(
    "direct_post.jwt",
    "iar-post.jwt",
    "iae_post.jwt"
).forEach { responseMode ->
            val modifiedParams = createV1DcqlParams(responseMode, requireHolderBinding = true, includeState = false)

            assertDoesNotThrow {
                createHandler(modifiedParams, SpecVersion.V1).validateAndParseRequestFields()
            }
        }
    }

    @Test
    fun `validateAndParseRequestFields should require state for v1 jwt response modes when holder binding is disabled`() {
        listOf(
    "direct_post.jwt",
    "iar-post.jwt",
    "iae_post.jwt"
).forEach { responseMode ->
            val modifiedParams = createV1DcqlParams(responseMode, requireHolderBinding = false, includeState = false)

            val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
                createHandler(modifiedParams, SpecVersion.V1).validateAndParseRequestFields()
            }
            assertTrue(exception.message?.contains("state") == true)
        }
    }

    @Test
    fun `validateAndParseRequestFields should succeed with direct_post_jwt response mode`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = "direct_post.jwt"
        assertDoesNotThrow { createHandler(modifiedParams).validateAndParseRequestFields() }
    }

    @Test
    fun `validateAndParseRequestFields should throw exception with unsupported response mode`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = "unsupported_mode"
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(modifiedParams).validateAndParseRequestFields()
        }
        assertOpenId4VPException(
            exception,
            "Given response_mode - unsupported_mode is not supported",
            "invalid_request"
        )
    }

    @Test
    fun `validateAndParseRequestFields should throw exception when response_mode is missing`() {
        mockkStatic("io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataUtilKt")
        mockkStatic("io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionUtilKt")
        every { parseAndValidatePresentationDefinition(any(), any()) } just runs

        val modifiedParams = authorizationRequestParameters.toMutableMap().apply { remove(RESPONSE_MODE.value) }
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            createHandler(modifiedParams).validateAndParseRequestFields()
        }
        assertTrue(exception.message?.contains("response_mode") == true)
        unmockkStatic("io.mosip.openID4VP.authorizationRequest.clientMetadata.ClientMetadataUtilKt")
    }

    @Test
    fun `setResponseUrl should throw exception when REDIRECT_URI is present for direct_post`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[REDIRECT_URI.value] = "https://example.com/redirect"
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(modifiedParams).prepareDispatchInfo()
        }
        assertTrue(exception.message?.contains("redirect_uri should not be present") == true)
    }

    @Test
    fun `setResponseUrl should throw exception when REDIRECT_URI is present for direct_post_jwt`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = "direct_post.jwt"
        modifiedParams[REDIRECT_URI.value] = "https://example.com/redirect"
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(modifiedParams).prepareDispatchInfo()
        }
        assertTrue(exception.message?.contains("redirect_uri should not be present") == true)
    }

    @Test
    fun `validateClientAuthenticity should use client_id as response_uri when RESPONSE_URI is missing`() {
        listOf("direct_post", "direct_post.jwt").forEach { responseMode ->
            val modifiedParams = authorizationRequestParameters.toMutableMap()
            modifiedParams[RESPONSE_MODE.value] = responseMode
            modifiedParams.remove(RESPONSE_URI.value)

            assertDoesNotThrow { createHandler(modifiedParams).validateClientAuthenticity() }
            assertEquals(responseUrl, modifiedParams[RESPONSE_URI.value])
        }
    }

    @Test
    fun `authorization request should carry client_id as response_uri when RESPONSE_URI is missing`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams.remove(RESPONSE_URI.value)
        val handler = createHandler(modifiedParams)

        handler.validateClientAuthenticity()
        assertDoesNotThrow { handler.prepareDispatchInfo() }
        handler.validateAndParseRequestFields()

        assertEquals(responseUrl, handler.createAuthorizationRequest().responseUri)
    }

    @Test
    fun `validateClientAuthenticity should throw exception when RESPONSE_URI is empty`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_URI.value] = ""
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            createHandler(modifiedParams).validateClientAuthenticity()
        }
        assertTrue(exception.message?.contains("response_uri") == true)
    }

    @Test
    fun `validateClientAuthenticity should throw exception when RESPONSE_URI doesn't match CLIENT_ID`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_URI.value] = "https://different-domain.com/response"
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(modifiedParams).validateClientAuthenticity()
        }
        assertOpenId4VPException(
            exception,
            "response_uri should be equal to client_id for given client_id_prefix",
            "invalid_request"
        )
    }

  @Test
fun `validateClientAuthenticity should succeed with IAR and IAE response modes`() {
    listOf(
        "iar-post",
        "iar-post.jwt",
        "iae_post",
        "iae_post.jwt"
    ).forEach { responseMode ->
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = responseMode

        assertDoesNotThrow {
            createHandler(modifiedParams).validateClientAuthenticity()
        }
    }
}
 @Test
fun `validateAndParseRequestFields should succeed with IAR and IAE response modes when redirect_uri is present`() {
    listOf(
        "iar-post",
        "iar-post.jwt",
        "iae_post",
        "iae_post.jwt"
    ).forEach { responseMode ->
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = responseMode
        modifiedParams[REDIRECT_URI.value] = "https://example.com/redirect"

        assertDoesNotThrow {
            createHandler(modifiedParams).validateAndParseRequestFields()
        }
    }
}

    @Test
fun `validateAndParseRequestFields should succeed with IAR and IAE response modes when response_uri is missing`() {
    listOf(
        "iar-post",
        "iar-post.jwt",
        "iae_post",
        "iae_post.jwt"
    ).forEach { responseMode ->
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = responseMode
        modifiedParams.remove(RESPONSE_URI.value)

        assertDoesNotThrow {
            createHandler(modifiedParams).validateAndParseRequestFields()
        }
    }
}

  @Test
fun `validateAndParseRequestFields should succeed with IAR and IAE response modes when response_uri doesn't match client_id`() {
    listOf(
        "iar-post",
        "iar-post.jwt",
        "iae_post",
        "iae_post.jwt"
    ).forEach { responseMode ->
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = responseMode
        modifiedParams[RESPONSE_URI.value] = "https://different-domain.com/response"

        assertDoesNotThrow {
            createHandler(modifiedParams).validateAndParseRequestFields()
        }
    }
}

    @Test
    fun `validateClientAuthenticity rejects an unsupported response mode`() {
        val modifiedParams = authorizationRequestParameters.toMutableMap()
        modifiedParams[RESPONSE_MODE.value] = "unsupported_mode"

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            createHandler(modifiedParams).validateClientAuthenticity()
        }
        assertOpenId4VPException(
            exception,
            "Given response_mode - unsupported_mode is not supported",
            "invalid_request"
        )
    }
}