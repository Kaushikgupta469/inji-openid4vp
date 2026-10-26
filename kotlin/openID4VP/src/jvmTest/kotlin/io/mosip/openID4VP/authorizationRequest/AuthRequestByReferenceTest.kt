package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo

import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.just
import io.mockk.mockkConstructor
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.runs
import io.mockk.verify
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwks
import io.mosip.openID4VP.common.resolveJwksFromUri
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdPrefix.DECENTRALIZED_IDENTIFIER
import io.mosip.openID4VP.constants.ClientIdPrefix.PRE_REGISTERED
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.HttpMethod.GET
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.MismatchingClientIDInRequest
import io.mosip.openID4VP.jwt.jws.JWSHandler
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.assertDoesNotThrow
import io.mosip.openID4VP.testData.authRequestWithRedirectUriByValue
import io.mosip.openID4VP.testData.clientIdOfDid
import io.mosip.openID4VP.testData.clientIdOfPreRegistered
import io.mosip.openID4VP.testData.clientIdOfReDirectUriDraft23
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.createUrlEncodedData
import io.mosip.openID4VP.testData.didPublicKey
import io.mosip.openID4VP.testData.didResponse
import io.mosip.openID4VP.testData.jwkList
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.requestParams
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.trustedVerifiers
import io.mosip.openID4VP.testData.walletConfig
import io.mosip.openID4VP.testData.walletNonce
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.Assert.assertTrue
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AuthRequestByReferenceTest {

    private lateinit var openID4VP: OpenID4VP

    @BeforeTest
    fun setUp() {
        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig(trustedVerifiers = trustedVerifiers))

        mockkStatic("io.mosip.openID4VP.authorizationRequest.AuthorizationRequestUtilsKt")
        every { validateWalletNonce(any(), any()) } just runs

        // Mock did resolution
        mockkConstructor(DidPublicKeyResolver::class)
        every {
            anyConstructed<DidPublicKeyResolver>().resolve(
                "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs",
                "did:web:mosip.github.io:inji-mock-services:openid4vp-service:docs#key-0"
            )
        } returns didPublicKey

        mockkObject(NetworkManagerClient.Companion)
        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                GET
            )
        } returns NetworkResponse(200, presentationDefinitionString, emptyMap())

        mockkStatic("io.mosip.openID4VP.common.UtilsKt")
        every { resolveJwksFromUri(any(), any()) } returns Jwks(jwkList)
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should make call to request_uri with the request_uri_method when the fields are available in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any(),
                headers = any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(DECENTRALIZED_IDENTIFIER, authorizationRequestParamsMap).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, ClientIdPrefix.REDIRECT_URI)


        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                GET,
                null,
                match { it["accept"] == "application/oauth-authz-req+jwt" }
            )
        }
    }

    @Test
    fun `should send wallet metadata to the verifier only when the request_uri_method is post`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            "request_uri_method" to "post"
        )

        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.POST,
                any(),
                any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(DECENTRALIZED_IDENTIFIER, authorizationRequestParamsMap).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )


        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        val openID4VP = OpenID4VP("test-OpenID4VP", walletConfig)

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                HttpMethod.POST,
                any(),
                any()
            )
        }
    }


    @Test
    fun `should throw exception when the client_id validation fails while obtaining Authorization request object by reference in did client id scheme`() {
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, any(), headers = any())
        } returns NetworkResponse(
            200, createAuthorizationRequestObject(
                DECENTRALIZED_IDENTIFIER, requestParams + mapOf(
                    CLIENT_ID.value to "wrong-client-id",
                    "client_id_scheme" to "did"
                )
            ).toString(), mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, DECENTRALIZED_IDENTIFIER)


        val exception = assertFailsWith<MismatchingClientIDInRequest> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }

    @Test
    fun `should make a call to request_uri in get http call if request_uri_method is not available in did client id scheme`() {
        val authorizationRequestParamsMap =
            requestParams.minus("request_uri_method") + clientIdOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any(),
                headers = any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(DECENTRALIZED_IDENTIFIER, authorizationRequestParamsMap).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        openID4VP.authenticateVerifier(
            encodedAuthorizationRequest
        )

        verify {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                GET,
                null,
                match { it["accept"] == "application/oauth-authz-req+jwt" }
            )
        }

    }


    //Client Id scheme - DECENTRALIZED_IDENTIFIER
    @Test
    fun `should return Authorization Request if it has request uri and it is a valid authorization request in did client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any(),
                headers = any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(DECENTRALIZED_IDENTIFIER, authorizationRequestParamsMap).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                DECENTRALIZED_IDENTIFIER
            )

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
    }

    //Client Id scheme - DECENTRALIZED_IDENTIFIER
    @Test
    fun `should return Authorization Request with populated clientIdScheme(did) field if the verifier is draft 21 compliant`() {
        val authorizationRequestParamsMap =
            requestParams + clientIdOfDid + mapOf("client_id_scheme" to "did")
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any(),
                headers = any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(
                DECENTRALIZED_IDENTIFIER,
                authorizationRequestParamsMap,
                draftVersion = 21
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                true,
                DECENTRALIZED_IDENTIFIER,
                draftVersion = 21
            )

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
    }


    @Test
    fun `should validate request_uri response with valid JWS and correct content type for DECENTRALIZED_IDENTIFIER scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val validJwt = createAuthorizationRequestObject(
            clientIdScheme = DECENTRALIZED_IDENTIFIER,
            authorizationRequestParamsMap,
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, GET, headers = any())
        } returns NetworkResponse(
            200,
            validJwt.toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
    }


    @Test

    fun `should throw exception when content-type is invalid in request_uri response`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val validJwt = createAuthorizationRequestObject(
            clientIdScheme = DECENTRALIZED_IDENTIFIER,
            authorizationRequestParamsMap
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, GET, headers = any())
        } returns NetworkResponse(
            200,
            validJwt.toString(),
            mapOf("content-type" to listOf("application/json"))
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertEquals(
            "Authorization Request Object must have content type 'application/oauth-authz-req+jwt'",
            exception.message
        )
    }

    @Test
    fun `should throw exception when Authorization Request Object is not a signed JWT`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val unsignedJwt = "not.a.valid.jwt"

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, GET, headers = any())
        } returns NetworkResponse(
            200,
            unsignedJwt,
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertEquals(
            "Authorization Request Object must be a signed JWT",
            exception.message
        )
    }

    @Test
    fun `should throw exception when JWS signature verification fails`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val invalidSignedJwt = createAuthorizationRequestObject(
            clientIdScheme = DECENTRALIZED_IDENTIFIER,
            authorizationRequestParamsMap
        )

        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mosip.github.io/inji-mock-services/openid4vp-service/docs/did.json",
                GET
            )
        } returns NetworkResponse(200, didResponse, emptyMap())
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, GET, headers = any())
        } returns NetworkResponse(
            200,
            invalidSignedJwt.toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )


        mockkObject(JWSHandler)
        every {
            JWSHandler.verify(any(), any(), any())
        } throws RuntimeException("Invalid signature")

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertTrue(exception.message.contains("JWS signature verification failed"))
    }

    //
    @Test
    fun `should throw exception when request_uri response is empty`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, GET, headers = any())
        } returns NetworkResponse(200, "", emptyMap())

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
        print(exception.message)
        assertEquals(
            "Missing body in request_uri response",
            exception.message
        )
    }

    @Test
    fun `should throw exception when signing algorithm is not supported`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val jwtWithUnsupportedAlg = createAuthorizationRequestObject(
            clientIdScheme = DECENTRALIZED_IDENTIFIER,
            authorizationRequestParamsMap,
            jwtHeader = buildJsonObject {
                put("alg", "HS256")
                put("typ", "oauth-authz-req+jwt")
            }
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, GET, headers = any())
        } returns NetworkResponse(
            200,
            jwtWithUnsupportedAlg.toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        val exception = assertFailsWith<OpenID4VPExceptions.VerificationFailure> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertEquals(
            "Request URI response validation failed No enum constant io.mosip.openID4VP.constants.SignatureAlgorithm.HS256",
            exception.message
        )
    }


    @Test
    fun `should return Authorization Request with populated clientIdScheme(pre-registered) field if the verifier is draft 21 compliant`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered + mapOf(
            "client_id_scheme" to "pre-registered"
        )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any(),
                headers = any()
            )
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap,
                draftVersion = 21,
                jwtHeader = buildJsonObject {
                    put("typ", "oauth-authz-req+jwt")
                    put("alg", "EdDSA")
                },
                isPresentationDefinitionUriPresent = true
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            PRE_REGISTERED,
            draftVersion = 21
        )


        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest,
            )
        }
    }


    @Test
    fun `should throw exception when body is missing in request_uri response`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, GET, headers = any())
        } returns NetworkResponse(
            200,
            "",
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, DECENTRALIZED_IDENTIFIER)

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertEquals("Missing body in request_uri response", exception.message)
    }

    @Test
    fun `should throw exception when wallet_nonce validation fails in POST flow`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "post"
        )

        val jwt = createAuthorizationRequestObject(DECENTRALIZED_IDENTIFIER, authorizationRequestParamsMap)

        mockkStatic("io.mosip.openID4VP.authorizationRequest.AuthorizationRequestUtilsKt")
        every {
            validateWalletNonce(
                any(),
                any()
            )
        } throws IllegalArgumentException("wallet_nonce mismatch")

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns NetworkResponse(
            200,
            jwt.toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            true,
            DECENTRALIZED_IDENTIFIER
        )

        val exception = assertFailsWith<InvalidData> {
            OpenID4VP("test", walletConfig).authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertTrue(exception.message.contains("Wallet nonce validation failed"))
    }

    @Test
    fun `should throw exception when alg is missing in JWS header`() {
        val requestParamsMap = requestParams + clientIdOfDid + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI.value to requestUrl,
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "get"
        )

        val jwsWithoutAlg = createAuthorizationRequestObject(
            clientIdScheme = DECENTRALIZED_IDENTIFIER,
            requestParamsMap,
            jwtHeader = buildJsonObject { put("typ", "oauth-authz-req+jwt") }
        )

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, GET, headers = any())
        } returns NetworkResponse(
            200,
            jwsWithoutAlg.toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encoded = createUrlEncodedData(requestParamsMap, true, DECENTRALIZED_IDENTIFIER)

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(encoded)
        }

        assertEquals(
            "Request URI response validation failed - 'alg' is not present in JWS header",
            exception.message
        )
    }

//MARK: Pre-registered

    //Client Id scheme - Pre-registered
    @Test
    fun `should return back authorization request successfully when authorization request is obtained by reference in pre-registered client id scheme`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                GET,
                any(),
                any()
            )
        } returns NetworkResponse(
            200, createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap,
                jwtHeader = jwtHeader,
                isPresentationDefinitionUriPresent = true
            ).toString(), mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)


        assertDoesNotThrow {
            AuthorizationRequest.validateAndCreateAuthorizationRequest(
                encodedAuthorizationRequest,
                WalletConfig(trustedVerifiers = trustedVerifiers),
                { _: ResponseDispatchInfo -> },
                walletNonce
            )
        }
    }

    //Client Id - Pre-registered
    @Test
    fun `should validate client_id when authorization request is obtained by reference in pre-registered client id scheme`() {
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, any(), headers = any())
        } returns NetworkResponse(
            200, createAuthorizationRequestObject(
                PRE_REGISTERED, requestParams + mapOf(
                    CLIENT_ID.value to "wrong-client-id",
                    "client_id_scheme" to "pre-registered",
                ),
                jwtHeader = jwtHeader
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        val invalidClientIdException =
            assertFailsWith<MismatchingClientIDInRequest> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            invalidClientIdException.message
        )
    }

    //Client Id - Pre-registered
    @Test
    fun `should succeed when alg is supported in wallet metadata`() {

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered +
                mapOf(AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "post")
        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig(trustedVerifiers = trustedVerifiers))
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns NetworkResponse(
            200, createAuthorizationRequestObject(
                PRE_REGISTERED, authorizationRequestParamsMap,
                jwtHeader = jwtHeader,
                isPresentationDefinitionUriPresent = true
            ).toString(), mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encoded = createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        openID4VP.authenticateVerifier(encoded)
    }

    @Test
    fun `should throw when alg is not-supported in wallet metadata`() {

        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig(trustedVerifiers = trustedVerifiers))
        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "ES256")
        }
        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns NetworkResponse(
            200,
            createAuthorizationRequestObject(
                PRE_REGISTERED, requestParams + clientIdOfPreRegistered + mapOf(
                    "request_uri_method" to "post"
                ),
                jwtHeader = jwtHeader
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encoded = createUrlEncodedData(
            requestParams + clientIdOfPreRegistered + mapOf(
                "request_uri_method" to "post"
            ), true, PRE_REGISTERED
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(encoded)
        }

        assertEquals(
            "Request URI response validation failed - request_object_signing_alg is not supported by wallet",
            exception.message
        )

    }

    @Test
    fun `should throw when client_id is missing in authorization request parameters`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "post"
        )

        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns NetworkResponse(
            200, createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap,
                jwtHeader = jwtHeader,

                ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encoded = createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            openID4VP.authenticateVerifier(encoded)
        }

        assertEquals(
            "Missing Input: client_id param is required",
            exception.message
        )
    }

    @Test
    fun `should throw when client_id is missing inside JWT claims`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered +
                mapOf(AuthorizationRequestFieldConstants.REQUEST_URI_METHOD.value to "post")

        val jwtHeader = buildJsonObject {
            put("typ", "oauth-authz-req+jwt")
            put("alg", "EdDSA")
        }

        every {
            NetworkManagerClient.sendHTTPRequest(requestUrl, HttpMethod.POST, any(), any())
        } returns NetworkResponse(
            200, createAuthorizationRequestObject(
                PRE_REGISTERED,
                authorizationRequestParamsMap,
                jwtHeader = jwtHeader,

                removeClientId = true
            ).toString(),
            mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
        )

        val encoded = createUrlEncodedData(authorizationRequestParamsMap, true, PRE_REGISTERED)

        val exception = assertFailsWith<MismatchingClientIDInRequest> {
            openID4VP.authenticateVerifier(encoded)
        }

        assertEquals(
            "Client Id mismatch in Authorization Request parameter and the Request Object",
            exception.message
        )
    }


    //Client Id scheme - Redirect URI

    @Test
    fun `should fail if request_uri is used with redirect_uri scheme`() {
        val encoded = createUrlEncodedData(
            requestParams + clientIdOfReDirectUriDraft23,
            clientIdScheme = ClientIdPrefix.REDIRECT_URI,
            applicableFields = authRequestWithRedirectUriByValue + listOf("request_uri")
        )

        val exception = assertFailsWith<InvalidData> {
            openID4VP.authenticateVerifier(encoded)
        }

        assertEquals(
            "Signed request (via request_uri) is not supported for given client_id_prefix - redirect_uri",
            exception.message
        )
    }
}