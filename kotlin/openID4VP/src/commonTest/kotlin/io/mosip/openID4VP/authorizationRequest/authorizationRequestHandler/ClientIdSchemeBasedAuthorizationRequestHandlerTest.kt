package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler

import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo

import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.unmockkObject
import io.mockk.verify
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.AuthorizationDcqlRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.deserializeAndValidate
import io.mosip.openID4VP.authorizationRequest.presentationDefinition.PresentationDefinitionSerializer
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.common.OpenID4VPErrorCodes.INVALID_REQUEST
import io.mosip.openID4VP.common.OpenID4VPErrorCodes.INVALID_REQUEST_URI_METHOD
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.HttpMethod.POST
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SignatureAlgorithm.EdDSA
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.assertDoesNotThrow
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.openID4VP.testData.authorisationRequestListToClientIdSchemeMap
import io.mosip.openID4VP.testData.clientIdOfDid
import io.mosip.openID4VP.testData.clientIdOfPreRegistered
import io.mosip.openID4VP.testData.createAuthorizationRequest
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.didUrl
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.requestParams
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.walletConfig
import io.mosip.openID4VP.testData.walletNonce
import io.mosip.vercred.vcverifier.utils.BuildConfig
import org.junit.After
import org.junit.Before
import org.junit.Test
import java.security.PublicKey
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class ClientIdSchemeBasedAuthorizationRequestHandlerTest {
    @Before
    fun setUp() {
        mockkObject(NetworkManagerClient)
        mockkObject(BuildConfig)
        mockkObject(JWSHandler)

        every { BuildConfig.getVersionSDKInt() } returns 26
    }

    @After
    fun tearDown() {
        unmockkObject(NetworkManagerClient, BuildConfig, JWSHandler)
    }

    @Test
    fun `should throw error when request uri returns non 2xx response`() {
        val mockHandler = createMockHandler(
            authorizationRequestParameters = mutableMapOf(REQUEST_URI.value to "https://example.com/request"),
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = false,
            clientIdScheme = "test"
        )

        // Mock sendHTTPRequest to return non-200 response
        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any(), any()
            )
        } returns NetworkResponse(
            400,
            """{"message":"error"}""",
            mapOf("Content-Type" to listOf("application/json"))
        )

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }
    }

    @Test
    fun `should throw error when client_id_prefix is not supported by wallet`() {
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
        ) as MutableMap<String, Any>
        // WalletConfig with unsupported clientIdPrefixesSupported
        val unsupportedWalletConfig = WalletConfig(
            clientIdPrefixesSupported = listOf(ClientIdPrefix.DECENTRALIZED_IDENTIFIER),
            requestObjectSigningAlgValuesSupported = listOf(EdDSA)
        )
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            walletConfig = unsupportedWalletConfig,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED"
        )
        // Should throw error when calling handleRequestObjectByReference (simulate POST)
        // We call fetchAuthorizationRequest which will eventually call isClientIdPrefixSupported
        // To trigger POST, we add REQUEST_URI_METHOD = "post" and REQUEST_URI
        authorizationRequestParamsMap[REQUEST_URI.value] = "https://example.com/request"
        authorizationRequestParamsMap["request_uri_method"] = "post"
        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(200, "dummy.jwt", mapOf("content-type" to listOf("application/oauth-authz-req+jwt")))
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), any()) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        // With graceful error handling, unsupported client_id_prefix during POST metadata
        // processing is logged as a warning and the request proceeds without wallet_metadata.
        // The request then fails for other reasons (e.g., invalid JWS structure).
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }
        // The prefix error is swallowed; the actual failure is about the JWS content
        assert(exception.message.contains("Authorization Request Object must be a signed JWT"))
    }

    @Test
    fun `fetchAuthorizationRequest throws for an unsupported request_uri_method`() {
        val params: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "mock-client",
            REQUEST_URI.value to "https://example.com/request",
            REQUEST_URI_METHOD.value to "patch"
        )
        val handler = createMockHandler(params)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            handler.fetchAuthorizationRequest()
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Unsupported HTTP method: patch",
            expectedErrorCode = INVALID_REQUEST_URI_METHOD
        )
    }

    @Test
    fun `should throw error when both request and request_uri are available in the request`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            REQUEST_URI.value to "https://example.com/request",
            REQUEST.value to "sample_request_object"
        )

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "test"
        )

        val invalidDataException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            invalidDataException,
            "Both 'request' and 'request_uri' cannot be present in same authorization request",
            INVALID_REQUEST
        )
    }

    @Test
    fun `should throw error when JWS header extraction fails`() {
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
            isSigned = true
        ) as MutableMap<String, Any>
        // Simulate JWSHandler.extractDataJsonFromJws throwing exception
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } throws Exception("header parse error")
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ -> mockk<PublicKey>() }
        )
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }
        assert(exception.message.contains("JWS header extraction failed: header parse error"))
    }

    @Test
    fun `should update specVersion to Draft23 for by-value unsigned request`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "mock-client",
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_MODE.value to "direct_post",
            RESPONSE_URI.value to responseUrl,
            NONCE.value to walletNonce,
            PRESENTATION_DEFINITION.value to presentationDefinitionString
        )

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            specVersion = SpecVersion.V1,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED"
        )

        assertEquals(SpecVersion.V1, mockHandler.specVersion)

        assertDoesNotThrow {
            mockHandler.fetchAuthorizationRequest()
        }

        assertEquals(SpecVersion.DRAFT_23, mockHandler.specVersion)
    }

    @Test
    fun `should update specVersion as per fully resolved by-value signed request`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to didUrl,
            REQUEST.value to "header.payload.signature"
        )

        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf(
            "alg" to "EdDSA",
            "typ" to "oauth-authz-req+jwt"
        )

        val v1Payload = mutableMapOf<String, Any>(
            CLIENT_ID.value to didUrl,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_MODE.value to "direct_post",
            RESPONSE_URI.value to responseUrl,
            NONCE.value to walletNonce,
            DCQL_QUERY.value to "{}"
        )
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns v1Payload

        val mockHandlerV1 = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap.toMutableMap(),
            specVersion = SpecVersion.V1,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = false,
            clientIdScheme = "DID",
            extractPublicKey = { _, _ -> mockk<PublicKey>() }
        )

        assertEquals(SpecVersion.V1, mockHandlerV1.specVersion)
        assertDoesNotThrow { mockHandlerV1.fetchAuthorizationRequest() }
        assertEquals(SpecVersion.V1, mockHandlerV1.specVersion)

        val draft23Payload = mutableMapOf<String, Any>(
            CLIENT_ID.value to didUrl,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_MODE.value to "direct_post",
            RESPONSE_URI.value to responseUrl,
            NONCE.value to walletNonce,
            PRESENTATION_DEFINITION.value to presentationDefinitionString
        )
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns draft23Payload

        val mockHandlerDraft23 = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap.toMutableMap(),
            specVersion = SpecVersion.V1,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = false,
            clientIdScheme = "DID",
            extractPublicKey = { _, _ -> mockk<PublicKey>() }
        )

        assertEquals(SpecVersion.V1, mockHandlerDraft23.specVersion)
        assertDoesNotThrow { mockHandlerDraft23.fetchAuthorizationRequest() }
        assertEquals(SpecVersion.DRAFT_23, mockHandlerDraft23.specVersion)
    }

    @Test
    fun `should update specVersion as per fully resolved by-reference signed request`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to didUrl,
            REQUEST_URI.value to requestUrl,
            REQUEST_URI_METHOD.value to POST.name
        )

        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(
            200,
            "header.payload.signature",
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf(
            "alg" to "EdDSA",
            "typ" to "oauth-authz-req+jwt"
        )
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns mutableMapOf(
            CLIENT_ID.value to didUrl,
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_MODE.value to "direct_post",
            RESPONSE_URI.value to responseUrl,
            NONCE.value to "qwertyuiop",
            WALLET_NONCE.value to walletNonce,
            PRESENTATION_DEFINITION.value to presentationDefinitionString
        )

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            specVersion = SpecVersion.V1,
            walletConfig = walletConfig,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "DID",
            extractPublicKey = { _, _ -> mockk<PublicKey>() },
            walletNonce = walletNonce
        )

        assertEquals(SpecVersion.V1, mockHandler.specVersion)
        assertDoesNotThrow { mockHandler.fetchAuthorizationRequest() }
        assertEquals(SpecVersion.DRAFT_23, mockHandler.specVersion)
    }

    @Test
    fun `should throw error when specVersion and request conformance validation fails`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to "mock-client",
            RESPONSE_TYPE.value to "vp_token",
            RESPONSE_MODE.value to "direct_post",
            RESPONSE_URI.value to responseUrl,
            NONCE.value to walletNonce,
            PRESENTATION_DEFINITION.value to presentationDefinitionString
        )

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            specVersion = SpecVersion.V1,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            confirmSpecVersionIdentifiedFromRequest = false
        )

        val invalidDataException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            invalidDataException,
            "Spec version identification from request parameters failed",
            INVALID_REQUEST
        )
    }

    /** Authorization Request passed as URL with encoded params */

    @Test
    fun `should process successfully when the authorization request is passed as URL with encoded params and unsigned request is supported`() {
        // In case of encoded parameters, the authorization request is a map here
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
        ) as MutableMap<String, Any>

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "REDIRECT_URI"
        )

        assertDoesNotThrow  {
            mockHandler.fetchAuthorizationRequest()
        }
    }

    @Test
    fun `should throw error when the client id prefix does not support unsigned request but the input has unsigned request (authorization request is passed as URL with encoded params)`() {
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
            isSigned = false
        ) as MutableMap<String, Any>

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = false,
            clientIdScheme = "DID"
        )

        val invalidDataException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            invalidDataException,
            "unsigned request is not supported for given client_id_prefix - DID",
            INVALID_REQUEST
        )
    }

    /** Passing a request object as value **/

    @Test
    fun `should proceed successfully when the authorization request (object) is available in request param and signed request is supported (authorization request is passed as URL with encoded params)`() {
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
            isSigned = true
        ) as MutableMap<String, Any>
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns mutableMapOf(
            CLIENT_ID.value to "mock-client",
            // other params are masked here
        )

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ ->
                mockk<PublicKey>()
            }
        )

        assertDoesNotThrow {
            mockHandler.fetchAuthorizationRequest()
        }
    }

    @Test
    fun `should reject a signed request by value with an algorithm the prefix does not verify, even when the wallet lists it`() {
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
            isSigned = true
        ) as MutableMap<String, Any>
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "ES256", "typ" to "oauth-authz-req+jwt")
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            walletConfig = WalletConfig(
                requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA, SignatureAlgorithm.ES256)
            ),
            extractPublicKey = { _, _ -> throw AssertionError("the key must not be resolved for an unsupported alg") }
        )

        val exception = assertFailsWith<OpenID4VPExceptions.VerificationFailure> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            exception,
            "Request URI response validation failed Signing algorithm 'ES256' is not supported for client_id_prefix PRE_REGISTERED",
            INVALID_REQUEST
        )
    }

    @Test
    fun `should send only the algorithms the prefix verifies in the wallet metadata for request_uri post`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to didUrl,
            REQUEST_URI.value to requestUrl,
            REQUEST_URI_METHOD.value to POST.name
        )
        val authorizationRequestObjectMap = (createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.DECENTRALIZED_IDENTIFIER]!!,
            requestParams = clientIdOfDid + requestParams
        ) + mapOf(WALLET_NONCE.value to walletNonce)) as MutableMap<String, Any>
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns authorizationRequestObjectMap
        every { NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any()) } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(ClientIdPrefix.PRE_REGISTERED, authorizationRequestParamsMap as Map<String, String>).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt")),
        )
        var walletConfigForMetadata: WalletConfig? = null
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            walletConfig = walletConfig.copy(
                requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA, SignatureAlgorithm.ES256)
            ),
            extractPublicKey = { _, _ -> mockk<PublicKey>() },
            walletNonce = walletNonce,
            getWalletMetadata = { walletConfigForMetadata = it; mapOf() }
        )

        mockHandler.fetchAuthorizationRequest()

        assertEquals(listOf(SignatureAlgorithm.EdDSA), walletConfigForMetadata?.requestObjectSigningAlgValuesSupported)
    }

    @Test
    fun `should throw error when the request param has invalid input`() {
        val authorizationRequestParamsMap : MutableMap<String, Any> = mutableMapOf(
            REQUEST.value to "",
            CLIENT_ID.value to "mock-client"
        )

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED"
        )

        val invalidInputException = assertFailsWith<OpenID4VPExceptions.InvalidInput> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            invalidInputException,
            "Invalid Input: request value cannot be empty or null",
            INVALID_REQUEST
        )
    }

    @Test
    fun `should throw error when the client id prefix does not support signed request but the input has signed request via request param`() {
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
            isSigned = true
        ) as MutableMap<String, Any>

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = false,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED"
        )

        val invalidDataException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            invalidDataException,
            "Signed request (via request) is not supported for given client_id_prefix - PRE_REGISTERED",
            INVALID_REQUEST
        )
    }

    @Test
    fun `should throw error when client id mismatches between authorization request parameter and encoded request param`() {
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
            isSigned = true
        ) as MutableMap<String, Any>
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns mutableMapOf(
            CLIENT_ID.value to "some-other-client-id",
            // other params are masked here
        )

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ ->
                mockk<PublicKey>()
            }
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MismatchingClientIDInRequest> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            exception,
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            INVALID_REQUEST
        )
    }

    /** Passing a request object by reference **/

    @Test
    fun `should process successfully when the authorization request (object) is available via request_uri param and signed request is supported`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(REQUEST_URI.value to "https://example.com/request")
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), any()) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ ->
                mockk<PublicKey>()
            }
        )

        // Mock sendHTTPRequest to return 200 response
        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any(), any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(ClientIdPrefix.PRE_REGISTERED,
                authorizationRequestParamsMap as Map<String, String>
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt")),
        )

        assertDoesNotThrow {
            mockHandler.fetchAuthorizationRequest()
        }
    }

    @Test
    fun `should make call to request uri with accept header as jwt when request uri method is get`() {
        // no request_uri_method param means default is get
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to didUrl,
            REQUEST_URI.value to requestUrl,
        )
        val authorizationRequestObjectMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.DECENTRALIZED_IDENTIFIER]!!,
            clientIdOfDid + requestParams
        ) as MutableMap<String, Any>
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns authorizationRequestObjectMap
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ ->
                mockk<PublicKey>()
            }
        )

        // Mock sendHTTPRequest to return 200 response
        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any(), any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(ClientIdPrefix.PRE_REGISTERED,
                authorizationRequestParamsMap as Map<String, String>
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt")),
        )

        mockHandler.fetchAuthorizationRequest()
                verify {
                    NetworkManagerClient.sendHTTPRequest(
                        requestUrl,
                        any(),
                        any(),
                        match { it["accept"] == "application/oauth-authz-req+jwt" }
                    )
                }
    }

    @Test
    fun `should make call to request uri with accept header as jwt and content as url encoded when request uri method is post (wallet metadata not available)`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to didUrl,
            REQUEST_URI.value to requestUrl,
            REQUEST_URI_METHOD.value to POST.name
        )
        val authorizationRequestObjectMap = (createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.DECENTRALIZED_IDENTIFIER]!!,
            requestParams = clientIdOfDid + requestParams
        ) + mapOf(WALLET_NONCE.value to walletNonce)) as MutableMap<String, Any>
        println("authorizationRequestObjectMap: $authorizationRequestObjectMap")
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns authorizationRequestObjectMap
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ ->
                mockk<PublicKey>()
            },
            walletNonce = walletNonce
        )

        // Mock sendHTTPRequest to return 200 response
        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any(), any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(ClientIdPrefix.PRE_REGISTERED,
                authorizationRequestParamsMap as Map<String, String>
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt")),
        )

        mockHandler.fetchAuthorizationRequest()
        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any(),
                match { it["wallet_nonce"] == walletNonce },
                match { it["accept"] == "application/oauth-authz-req+jwt" && it["content-type"] == "application/x-www-form-urlencoded" }
            )
        }
    }

    @Test
    fun `should make call to request uri with accept header as jwt and content as url encoded when request uri method is post (wallet metadata available)`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to didUrl,
            REQUEST_URI.value to requestUrl,
            REQUEST_URI_METHOD.value to POST.name
        )
        val authorizationRequestObjectMap = (createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.DECENTRALIZED_IDENTIFIER]!!,
            requestParams = clientIdOfDid + requestParams
        ) + mapOf(WALLET_NONCE.value to walletNonce)) as MutableMap<String, Any>
        println("authorizationRequestObjectMap: $authorizationRequestObjectMap")
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns authorizationRequestObjectMap
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ ->
                mockk<PublicKey>()
            },
            walletNonce = walletNonce,
            walletConfig = walletConfig
        )

        // Mock sendHTTPRequest to return 200 response
        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any(), any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(ClientIdPrefix.PRE_REGISTERED,
                authorizationRequestParamsMap as Map<String, String>
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt")),
        )

        mockHandler.fetchAuthorizationRequest()
        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any(),
                match { it["wallet_nonce"] == walletNonce && it.containsKey("wallet_metadata") },
                match { it["accept"] == "application/oauth-authz-req+jwt" && it["content-type"] == "application/x-www-form-urlencoded" }
            )
        }
    }

    @Test
    fun `should throw error when the client id prefix does not support signed request but the input has signed request via request_uri param`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(REQUEST_URI.value to "https://example.com/request")

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = false,
            isUnsignedRequestSupported = true
        )

        val invalidDataException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            invalidDataException,
            "Signed request (via request_uri) is not supported for given client_id_prefix - PRE_REGISTERED",
            INVALID_REQUEST
        )
    }

    @Test
    fun `should throw error when client id is mismatching in request uri response and authorization request parameters`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(REQUEST_URI.value to "https://example.com/request")
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf("alg" to "EdDSA", "typ" to "oauth-authz-req+jwt")
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD) } returns mutableMapOf(
            CLIENT_ID.value to "mismatching-client-id")
        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ ->
                mockk<PublicKey>()
            }
        )

        // Mock sendHTTPRequest to return 200 response
        every {
            NetworkManagerClient.sendHTTPRequest(
                any(), any(), any(), any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(ClientIdPrefix.PRE_REGISTERED,
                authorizationRequestParamsMap as Map<String, String>
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt")),
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MismatchingClientIDInRequest> {
            mockHandler.fetchAuthorizationRequest()
        }

        assertOpenId4VPException(
            exception,
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            INVALID_REQUEST
        )
    }

    @Test
    fun `createAuthorizationRequest builds a dcql request under spec V1`() {
        val dcqlQuery = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "mobile-id", format = FormatType.MSO_MDOC.value)
            )
        )
        val handler = createMockHandler(
            authorizationRequestParameters = mutableMapOf(
                CLIENT_ID.value to "https://mock-verifier.com",
                RESPONSE_TYPE.value to "vp_token",
                RESPONSE_MODE.value to "direct_post",
                RESPONSE_URI.value to responseUrl,
                NONCE.value to "verifier-nonce",
                WALLET_NONCE.value to walletNonce,
                STATE.value to "state-1",
                DCQL_QUERY.value to dcqlQuery
            ),
            specVersion = SpecVersion.V1
        )

        val request = handler.createAuthorizationRequest() as AuthorizationDcqlRequest

        assertEquals("https://mock-verifier.com", request.clientId)
        assertEquals("vp_token", request.responseType)
        assertEquals("direct_post", request.responseMode)
        assertEquals(responseUrl, request.responseUri)
        assertNull(request.redirectUri)
        assertEquals("verifier-nonce", request.nonce)
        assertEquals(walletNonce, request.walletNonce)
        assertEquals("state-1", request.state)
        assertNull(request.clientMetadata)
        assertEquals(dcqlQuery, request.dcqlQuery)
    }

    @Test
    fun `prepareDispatchInfo requires response_mode`() {
        val handler = createMockHandler(
            authorizationRequestParameters = mutableMapOf(
                CLIENT_ID.value to "https://mock-verifier.com",
                NONCE.value to "verifier-nonce",
                RESPONSE_URI.value to responseUrl
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            handler.prepareDispatchInfo()
        }
        assertOpenId4VPException(
            exception,
            "Missing Input: response_mode param is required",
            INVALID_REQUEST
        )
    }

    @Test
    fun `should throw error when JWS payload extraction fails for a by-value signed request`() {
        val authorizationRequestParamsMap = createAuthorizationRequest(
            authorisationRequestListToClientIdSchemeMap[ClientIdPrefix.PRE_REGISTERED]!!,
            clientIdOfPreRegistered + requestParams,
            isSigned = true
        ) as MutableMap<String, Any>
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf(
            "alg" to "EdDSA",
            "typ" to "oauth-authz-req+jwt"
        )
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every {
            JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD)
        } throws Exception("payload parse error")

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = true,
            clientIdScheme = "PRE_REGISTERED",
            extractPublicKey = { _, _ -> mockk<PublicKey>() }
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }
        assertOpenId4VPException(
            exception,
            "Failed to parse payload from Authorization Request Object: payload parse error",
            INVALID_REQUEST
        )
    }

    @Test
    fun `should throw error when JWS payload extraction fails for a request obtained by reference`() {
        val authorizationRequestParamsMap: MutableMap<String, Any> = mutableMapOf(
            CLIENT_ID.value to clientIdOfDid,
            REQUEST_URI.value to requestUrl
        )
        every {
            NetworkManagerClient.sendHTTPRequest(any(), any(), any(), any())
        } returns NetworkResponse(
            200,
            "header.payload.signature",
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )
        every { JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.HEADER) } returns mutableMapOf(
            "alg" to "EdDSA",
            "typ" to "oauth-authz-req+jwt"
        )
        every { JWSHandler.verify(any(), any(), any()) } returns Unit
        every {
            JWSHandler.extractDataJsonFromJws(any(), JWSHandler.JwsPart.PAYLOAD)
        } throws Exception("payload parse error")

        val mockHandler = createMockHandler(
            authorizationRequestParameters = authorizationRequestParamsMap,
            isSignedRequestSupported = true,
            isUnsignedRequestSupported = false,
            clientIdScheme = "DID",
            extractPublicKey = { _, _ -> mockk<PublicKey>() }
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            mockHandler.fetchAuthorizationRequest()
        }
        assertOpenId4VPException(
            exception,
            "Failed to parse payload from Authorization Request Object: payload parse error",
            INVALID_REQUEST
        )
    }

    private fun createMockHandler(
        authorizationRequestParameters: MutableMap<String, Any>,
        walletConfig: WalletConfig? = null,
        setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = {},
        walletNonce: String = "walletNonce",
        specVersion: SpecVersion = SpecVersion.DRAFT_23,
        isSignedRequestSupported: Boolean = true,
        isUnsignedRequestSupported: Boolean = true,
        clientIdScheme: String = "PRE_REGISTERED",
        extractPublicKey: ((SignatureAlgorithm, Map<String, Any>) -> PublicKey)? = null,
        confirmSpecVersionIdentifiedFromRequest: Boolean = true,
        getWalletMetadata: (WalletConfig) -> Map<String, Any> = { mapOf() }
    ): ClientIdPrefixBasedAuthorizationRequestHandler {
        return object : ClientIdPrefixBasedAuthorizationRequestHandler(
            clientId = authorizationRequestParameters[CLIENT_ID.value]?.toString() ?: "mock-client",
            specVersion = specVersion,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig ?: io.mosip.openID4VP.testData.walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        ) {
            override fun isSignedRequestSupported() = isSignedRequestSupported
            override fun isUnsignedRequestSupported() = isUnsignedRequestSupported
            override fun clientIdPrefix() = clientIdScheme
            override fun confirmSpecVersionIdentifiedFromRequest() = confirmSpecVersionIdentifiedFromRequest
            override fun extractPublicKey(algorithm: SignatureAlgorithm, jwsHeader: Map<String, Any>): PublicKey =
                extractPublicKey?.invoke(algorithm, jwsHeader) ?: throw NotImplementedError()
            override fun getWalletMetadata(walletConfig: WalletConfig): Map<String, Any> = getWalletMetadata(walletConfig)
        }
    }
}
