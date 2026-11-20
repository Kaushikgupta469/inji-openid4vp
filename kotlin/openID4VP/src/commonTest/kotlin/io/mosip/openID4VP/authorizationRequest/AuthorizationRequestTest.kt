package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo


import io.mockk.clearAllMocks
import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.PreRegisteredSchemeAuthorizationRequestHandler
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.common.OpenID4VPErrorCodes.INVALID_TRANSACTION_DATA
import io.mosip.openID4VP.constants.ClientIdPrefix.DECENTRALIZED_IDENTIFIER
import io.mosip.openID4VP.constants.ClientIdPrefix.PRE_REGISTERED
import io.mosip.openID4VP.constants.ClientIdPrefix.REDIRECT_URI
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.networkManager.exception.NetworkManagerClientExceptions.NetworkRequestFailed
import io.mosip.openID4VP.testData.assertDoesNotThrow
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.openID4VP.testData.authRequestWithRedirectUriByValue
import io.mosip.openID4VP.testData.clientIdOfPreRegistered
import io.mosip.openID4VP.testData.clientIdOfReDirectUriDraft23
import io.mosip.openID4VP.testData.createAuthorizationRequestObject
import io.mosip.openID4VP.testData.createUrlEncodedData
import io.mosip.openID4VP.testData.presentationDefinitionString
import io.mosip.openID4VP.testData.requestParams
import io.mosip.openID4VP.testData.requestUrl
import io.mosip.openID4VP.testData.responseUrl
import io.mosip.openID4VP.testData.trustedVerifiers
import io.mosip.openID4VP.testData.walletNonce
import kotlin.test.*


class AuthorizationRequestTest {
    private lateinit var openID4VP: OpenID4VP
    private lateinit var actualException: OpenID4VPExceptions
    private lateinit var expectedExceptionMessage: String

    @BeforeTest
    fun setUp() {
        mockkStatic("io.mosip.openID4VP.common.EncoderKt")
        every { encodeToBase64Url(any()) } answers { java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(firstArg()) }
        mockkStatic("io.mosip.openID4VP.common.DecoderKt")
        every { decodeFromBase64Url(any()) } answers { java.util.Base64.getUrlDecoder().decode(firstArg<String>()) }
        mockkObject(NetworkManagerClient)
        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig(trustedVerifiers = trustedVerifiers))
        

        every {
            NetworkManagerClient.sendHTTPRequest(
                "https://mock-verifier.com/verifier/get-presentation-definition",
                HttpMethod.GET
            )
        } returns NetworkResponse(200, presentationDefinitionString, mapOf())
    }

    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `should throw missing input exception if client_id param is missing in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams.minus(CLIENT_ID.value) + mapOf(
            "client_id_scheme" to "did"
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , DECENTRALIZED_IDENTIFIER)

        expectedExceptionMessage = "Missing Input: client_id param is required"

        actualException =
            assertFailsWith<OpenID4VPExceptions.MissingInput> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is empty string`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to "",
        )
        val encodedAuthorizationRequest = createUrlEncodedData(
            requestParams = authorizationRequestParamsMap,
            clientIdScheme = PRE_REGISTERED,
            verifierSentAuthRequestByReference = false
        )

        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid input exception if client_id param is present in Authorization Request but it's value is null`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            "client_id" to null,
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , DECENTRALIZED_IDENTIFIER)

        expectedExceptionMessage = "Invalid Input: client_id value cannot be an empty string, null, or an integer"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidInput> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if neither presentation_definition nor presentation_definition_uri param present in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams.minus(PRESENTATION_DEFINITION.value) + clientIdOfReDirectUriDraft23
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,
                false,
                REDIRECT_URI
            )

        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param must be present"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if both presentation_definition and presentation_definition_uri request params are present in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val applicableFields = listOf(
            CLIENT_ID.value,
            "client_id_scheme",
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap, false, PRE_REGISTERED, applicableFields
            )

        val expectedExceptionMessage =
            "Either presentation_definition or presentation_definition_uri request param can be provided but not both"
        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if received client_id is not matching with predefined Verifiers list client_id`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "mock-client-1",
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED)

        val expectedExceptionMessage =
            "Verifier is not trusted by the wallet"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidVerifier> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_CLIENT, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw exception if the url encoded authorization request is invalid`() {

        val encodedAuthorizationRequest ="@#$$#@"

        val expectedExceptionMessage =
            "Exception occurred when extracting the query params from Authorization Request : Illegal character in fragment at index 4: @#$$#@"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidQueryParams> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw invalid limit disclosure exception if limit disclosure is present and not matching with predefined values`() {
        val presentationDefinition =
            """{"id":"649d581c-f891-4969-9cd5-2c27385a348f","input_descriptors":[{"id":"idcardcredential","constraints":{"fields":[{"path":["$.type"]}], "limit_disclosure": "not preferred"}}]}"""

        val authorizationRequestParamsMap = requestParams+ clientIdOfReDirectUriDraft23 + mapOf(
            PRESENTATION_DEFINITION.value to presentationDefinition
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , REDIRECT_URI)

        val expectedExceptionMessage =
            "Invalid Input: constraints->limit_disclosure value should be preferred"

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidLimitDisclosure> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition & all the other fields are present and valid in Authorization Request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw error when client_id_scheme is redirect_uri and response_mode is absent`() {

        val authorizationRequestParamsMap = requestParams.minus(RESPONSE_MODE.value) + clientIdOfReDirectUriDraft23
        val applicableFields = listOf(
            CLIENT_ID.value,
            "client_id_scheme",
            REDIRECT_URI.value,
            PRESENTATION_DEFINITION.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value,
            RESPONSE_MODE.value
        )
        val expectedExceptionMessage = "Missing Input: response_mode param is required"

        val encodedAuthorizationRequest = createUrlEncodedData(
            authorizationRequestParamsMap,
            false,
            REDIRECT_URI,
            applicableFields
        )

        actualException =
        assertFailsWith<OpenID4VPExceptions.MissingInput> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error when client_id_scheme is redirect_uri and redirect_uri and client_id is different`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "redirect_uri:wrong-client-id"
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , REDIRECT_URI
            )

        val expectedExceptionMessage = "response_uri should be equal to client_id for given client_id_prefix"
        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                openID4VP.authenticateVerifier(
                    encodedAuthorizationRequest
                )
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if presentation_definition_uri & all the other fields are present and valid in Authorization Request`() {


        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered

        val applicableFields =  listOf(
            CLIENT_ID.value,
            "client_id_scheme",
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , PRE_REGISTERED, applicableFields
            )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should throw error if presentation_definition_uri is invalid in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23 + mapOf(PRESENTATION_DEFINITION_URI.value to "test-data")
        val applicableFields = listOf(
            CLIENT_ID.value,
            "client_id_scheme",
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                authorizationRequestParamsMap,false , REDIRECT_URI, applicableFields
            )

        actualException =
            assertFailsWith<OpenID4VPExceptions.InvalidData> {
                openID4VP.authenticateVerifier(encodedAuthorizationRequest)
            }
        assertEquals(OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI, actualException.errorCode)
        assertEquals("presentation_definition_uri is not valid",actualException.message)
    }

    @Test
    fun `should return Authorization Request as Authentication Response if all the fields are valid in Authorization Request and clientValidation is not needed`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23
        val encodedAuthorizationRequest =
            createUrlEncodedData(
                requestParams = authorizationRequestParamsMap,
                verifierSentAuthRequestByReference = false,
                clientIdScheme = REDIRECT_URI
            )

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest)
        assertTrue(actualValue is AuthorizationRequest)
    }

    @Test
    fun `should get presentation definition  by making api call if presentation_definition_uri is present in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                "client_id_scheme",
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns NetworkResponse(200, createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, applicationFields).toString(), mapOf("content-type" to listOf("application/oauth-authz-req+jwt")))


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED, applicationFields)


        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

    }

    @Test
    fun `should add default client id scheme as pre-registered if not present in authorization request`() {
        val authorizationRequestParamsMap = requestParams +  mapOf(
            CLIENT_ID.value to "mock-client",
        )
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                "client_id_scheme",
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns  NetworkResponse(
                    200,
                    createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, applicationFields).toString(),
                    mapOf("content-type" to listOf("application/oauth-authz-req+jwt"))
                )


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED, applicationFields)

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

    }

    @Test
    fun `should return Authorization Request for redirect uri scheme when passed by value`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , REDIRECT_URI)

        assertDoesNotThrow {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
    }

    @Test
    fun `should use client_id as response_uri for redirect uri scheme when response_uri is omitted`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfReDirectUriDraft23
        val applicableFields = authRequestWithRedirectUriByValue - RESPONSE_URI.value

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, false, REDIRECT_URI, applicableFields)

        val authorizationRequest = openID4VP.authenticateVerifier(encodedAuthorizationRequest)

        assertEquals(responseUrl, authorizationRequest.responseUri)
    }

    @Test
    fun `should throw error if response mode is not present in the authorization request`() {
        val authorizationRequestParamsMap = requestParams.minus(RESPONSE_MODE.value) + clientIdOfReDirectUriDraft23

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , REDIRECT_URI)

        expectedExceptionMessage = "Missing Input: response_mode param is required"
        actualException = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if response mode is not valid in the authorization request`() {
        val authorizationRequestParamsMap = requestParams+ clientIdOfReDirectUriDraft23 + mapOf(RESPONSE_MODE.value to "wrong input")

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , REDIRECT_URI)

        expectedExceptionMessage = "Given response_mode - wrong input is not supported"
        actualException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if redirect uri field is present in the authorization request`() {
        val authorizationRequestParamsMap = requestParams+ clientIdOfReDirectUriDraft23 + mapOf(REDIRECT_URI.value to "wrong input")

        val applicableFields = listOf(
            CLIENT_ID.value,
            "client_id_scheme",
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value,
            CLIENT_METADATA.value,
            REDIRECT_URI.value,
            PRESENTATION_DEFINITION.value
        )

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , REDIRECT_URI, applicableFields)

        expectedExceptionMessage = "redirect_uri should not be present for given response_mode"
        actualException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST,actualException.errorCode)
        assertEquals(expectedExceptionMessage, actualException.message)
    }

    @Test
    fun `should throw error if api call of presentation_definition_uri fails in authorization request`() {
        val uri = "https://mock-verifier.com/verifier/get-presentation-definition-1"

        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered +
                mapOf(PRESENTATION_DEFINITION_URI.value to uri)

        val applicationFields = listOf(
            CLIENT_ID.value,
            "client_id_scheme",
            RESPONSE_MODE.value,
            RESPONSE_URI.value,
            PRESENTATION_DEFINITION_URI.value,
            RESPONSE_TYPE.value,
            NONCE.value,
            STATE.value
        )

        // Simulate network failure
        every {
            NetworkManagerClient.sendHTTPRequest(uri, HttpMethod.GET)
        } throws NetworkRequestFailed("Network request failed with error response - mock-verifier.com")

        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, false, PRE_REGISTERED, applicationFields)

        val expectedMessage = "presentation_definition_uri could not be reached: $uri. Error: Network request failed with error response - Network request failed with error response - mock-verifier.com"

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_PRESENTATION_DEFINITION_URI, exception.errorCode)
        assertEquals(expectedMessage, exception.message)
    }

    @Test
    fun `should throw error client id is not present in trusted verifier for pre registered client id scheme in authorization request`() {
        val authorizationRequestParamsMap = requestParams + clientIdOfPreRegistered
        val applicationFields =
            listOf(
                CLIENT_ID.value,
                "client_id_scheme",
                RESPONSE_MODE.value,
                RESPONSE_URI.value,
                PRESENTATION_DEFINITION_URI.value,
                RESPONSE_TYPE.value,
                NONCE.value,
                STATE.value,
                CLIENT_METADATA.value
            )
        every {
            NetworkManagerClient.sendHTTPRequest(
                requestUrl,
                any()
            )
        } returns NetworkResponse(200, createAuthorizationRequestObject(PRE_REGISTERED, authorizationRequestParamsMap, applicationFields).toString(), mapOf("content-type" to listOf("application/oauth-authz-req+jwt")))


        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap,false , PRE_REGISTERED, applicationFields)
        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig())
        assertFailsWith<OpenID4VPExceptions.InvalidVerifier> {
            openID4VP.authenticateVerifier(
                encodedAuthorizationRequest
            )
        }
    }

    @Test
    fun `should treat client_id with unrecognized prefix as pre-registered client`() {
        val clientIdWithUnknownPrefix = "foo:mock-client"
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to clientIdWithUnknownPrefix,
        )
        val verifiers = listOf(
            Verifier(
                clientId = clientIdWithUnknownPrefix,
                responseUris = listOf(responseUrl),
                allowUnsignedRequest = true,
                specVersion = SpecVersion.DRAFT_23
            )
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, false, PRE_REGISTERED)
        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig(trustedVerifiers = verifiers))

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest)

        assertEquals(clientIdWithUnknownPrefix, actualValue.clientId)
        assertEquals(responseUrl, actualValue.responseUri)
    }

    @Test
    fun `should validate trusted list for client_id with unrecognized prefix`() {
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to "foo:unknown-client",
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, false, PRE_REGISTERED)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidVerifier> {
            openID4VP.authenticateVerifier(encodedAuthorizationRequest)
        }

        assertOpenId4VPException(
            exception,
            "Verifier is not trusted by the wallet",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_CLIENT,
        )
    }

    @Test
    fun `should treat client_id with URL scheme as pre-registered client`() {
        val clientIdWithUrlScheme = "https://verifier.example.com"
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to clientIdWithUrlScheme,
        )
        val verifiers = listOf(
            Verifier(
                clientId = clientIdWithUrlScheme,
                responseUris = listOf(responseUrl),
                allowUnsignedRequest = true,
                specVersion = SpecVersion.DRAFT_23
            )
        )
        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig(trustedVerifiers = verifiers))
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, false, PRE_REGISTERED)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest)

        assertEquals(clientIdWithUrlScheme, actualValue.clientId)
        assertEquals(responseUrl, actualValue.responseUri)
    }

    @Test
    fun `should treat client_id without colon as pre-registered client`() {
        val plainClientId = "govt-verifier"
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to plainClientId,
        )
        val verifiers = listOf(
            Verifier(
                clientId = plainClientId,
                responseUris = listOf(responseUrl),
                allowUnsignedRequest = true,
                specVersion = SpecVersion.DRAFT_23
            )
        )
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, false, PRE_REGISTERED)
        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig(trustedVerifiers = verifiers))

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest)

        assertEquals(plainClientId, actualValue.clientId)
        assertEquals(responseUrl, actualValue.responseUri)
    }

    @Test
    fun `should treat explicit pre-registered prefix in client_id as pre-registered client`() {
        val clientIdWithExplicitPrefix = "pre-registered:foo"
        val authorizationRequestParamsMap = requestParams + mapOf(
            CLIENT_ID.value to clientIdWithExplicitPrefix,
        )
        val verifiers = listOf(
            Verifier(
                clientId = clientIdWithExplicitPrefix,
                responseUris = listOf(responseUrl),
                allowUnsignedRequest = true,
                specVersion = SpecVersion.DRAFT_23
            )
        )
        openID4VP = OpenID4VP("test-OpenID4VP", WalletConfig(trustedVerifiers = verifiers))
        val encodedAuthorizationRequest =
            createUrlEncodedData(authorizationRequestParamsMap, false, PRE_REGISTERED)

        val actualValue =
            openID4VP.authenticateVerifier(encodedAuthorizationRequest)

        assertEquals(clientIdWithExplicitPrefix, actualValue.clientId)
        assertEquals(responseUrl, actualValue.responseUri)
    }

    @Test
    fun `should throw invalid request exception if transaction_data is present in Authorization Request`() {
        val setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit = mockk(relaxed = true)

        val handler = PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = "mock-client",
            specVersion = SpecVersion.DRAFT_23,
            authorizationRequestParameters = (requestParams + clientIdOfPreRegistered + mapOf(
                "transaction_data" to "some_value",
            )) as MutableMap<String, Any>,
            walletConfig = WalletConfig(trustedVerifiers = listOf(
                Verifier(
                    "mock-client", listOf(
                        "https://mock-verifier.com/response-uri", "https://verifier.env2.com/responseUri"
                    ),
                    "https://mock-verifier.com/.well-known/jwks.json",
                    true
                ))),
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidTransactionData> {
            handler.validateAndParseRequestFields()
        }

        assertOpenId4VPException(
            exception, "Invalid Request: transaction_data is not supported in the authorization request",
            expectedErrorCode = INVALID_TRANSACTION_DATA,
        )
    }
}
