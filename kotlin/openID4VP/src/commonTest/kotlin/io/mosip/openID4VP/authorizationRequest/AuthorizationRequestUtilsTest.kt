package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.SpecVersion
import kotlin.test.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.DecentralizedIdentifierPrefixAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.PreRegisteredSchemeAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.RedirectUriPrefixAuthorizationRequestHandler
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Tests for AuthorizationRequestUtils.kt changes from PR #111:
 * - extractClientIdPrefix: infers prefix from client_id format
 * - extractClientIdPartOnly: extracts the actual client_id without prefix
 * - findSpecVersion: determines spec version from client_id_prefix and request params
 * - findSpecVersionUsingRequestParameters: determines spec version from dcql_query vs presentation_definition
 */
class AuthorizationRequestUtilsTest {

    // === extractClientIdPrefix ===

    @Test
    fun `extractClientIdPrefix returns pre-registered when client_id has no colon`() {
        val params = mapOf<String, Any>("client_id" to "my-client-id")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns redirect_uri when client_id starts with redirect_uri prefix`() {
        val params = mapOf<String, Any>("client_id" to "redirect_uri:https://example.com/callback")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.REDIRECT_URI.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns did when client_id starts with did prefix`() {
        val params = mapOf<String, Any>("client_id" to "did:web:example.com:service")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdScheme.DID.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns decentralized_identifier when client_id starts with that prefix`() {
        val params = mapOf<String, Any>("client_id" to "decentralized_identifier:did:web:example.com")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns pre-registered for simple alphanumeric client_id`() {
        val params = mapOf<String, Any>("client_id" to "verifier123")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns pre-registered when client_id has unrecognized prefix`() {
        val params = mapOf<String, Any>("client_id" to "foo:bar")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns pre-registered when client_id starts with URL scheme`() {
        val params = mapOf<String, Any>("client_id" to "https://verifier.example.com")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    @Test
    fun `extractClientIdPrefix returns pre-registered when client_id starts with pre-registered prefix`() {
        val params = mapOf<String, Any>("client_id" to "pre-registered:foo")
        val result = extractClientIdPrefix(params)
        assertEquals(ClientIdPrefix.PRE_REGISTERED.value, result)
    }

    // === extractClientIdPartOnly ===

    @Test
    fun `extractClientIdPartOnly returns full client_id for did prefix`() {
        val params = mapOf<String, Any>("client_id" to "did:web:mosip.github.io:service")
        val result = extractClientIdPartOnly(params)
        assertEquals("did:web:mosip.github.io:service", result)
    }

    @Test
    fun `extractClientIdPartOnly returns part after colon for redirect_uri prefix`() {
        val params = mapOf<String, Any>("client_id" to "redirect_uri:https://example.com/callback")
        val result = extractClientIdPartOnly(params)
        assertEquals("https://example.com/callback", result)
    }

    @Test
    fun `extractClientIdPartOnly returns DID URL after stripping decentralized_identifier prefix`() {
        val params = mapOf<String, Any>("client_id" to "decentralized_identifier:did:web:example.com")
        val result = extractClientIdPartOnly(params)
        // For V1 decentralized_identifier prefix, strip the prefix to get actual DID URL
        assertEquals("did:web:example.com", result)
    }

    @Test
    fun `extractClientIdPartOnly returns full client_id when no colon present`() {
        val params = mapOf<String, Any>("client_id" to "simple-client")
        val result = extractClientIdPartOnly(params)
        assertEquals("simple-client", result)
    }

    @Test
    fun `extractClientIdPartOnly returns full client_id for unrecognized prefix`() {
        val params = mapOf<String, Any>("client_id" to "foo:bar")
        val result = extractClientIdPartOnly(params)
        assertEquals("foo:bar", result)
    }

    @Test
    fun `extractClientIdPartOnly returns full client_id for URL scheme`() {
        val params = mapOf<String, Any>("client_id" to "https://verifier.example.com")
        val result = extractClientIdPartOnly(params)
        assertEquals("https://verifier.example.com", result)
    }

    // === findSpecVersionUsingRequestParameters ===

    @Test
    fun `findSpecVersionUsingRequestParameters returns V1 when dcql_query is present`() {
        val params = mapOf<String, Any>(
            "dcql_query" to "{}",
            "client_id" to "test"
        )
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.V1, result)
    }

    @Test
    fun `findSpecVersionUsingRequestParameters returns DRAFT_23 when presentation_definition is present`() {
        val params = mapOf<String, Any>(
            "presentation_definition" to "{}",
            "client_id" to "test"
        )
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.DRAFT_23, result)
    }

    @Test
    fun `findSpecVersionUsingRequestParameters returns DRAFT_23 when presentation_definition_uri is present`() {
        val params = mapOf<String, Any>(
            "presentation_definition_uri" to "https://example.com/pd",
            "client_id" to "test"
        )
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.DRAFT_23, result)
    }

    @Test
    fun `findSpecVersionUsingRequestParameters returns DRAFT_23 when neither dcql_query nor presentation_definition present`() {
        val params = mapOf<String, Any>("client_id" to "test")
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.DRAFT_23, result)
    }

    @Test
    fun `findSpecVersionUsingRequestParameters prefers dcql_query over presentation_definition`() {
        val params = mapOf<String, Any>(
            "dcql_query" to "{}",
            "presentation_definition" to "{}",
            "client_id" to "test"
        )
        val result = findSpecVersionUsingRequestParameters(params)
        assertEquals(SpecVersion.V1, result)
    }

    // === findSpecVersion ===

    @Test
    fun `findSpecVersion returns V1 for any prefix other than pre-registered or decentralized_identifier (did)`() {
        val params = mapOf<String, Any>(
            "presentation_definition" to "{}",
            "client_id" to "redirect_uri:https://example.com"
        )
        val result = findSpecVersionUsingClientId(
            clientId = "redirect_uri:https://example.com",
            clientIdPrefix = ClientIdPrefix.REDIRECT_URI.value,
            trustedVerifiers = emptyList()
        )
        assertEquals(SpecVersion.V1, result)
    }

    @Test
    fun `findSpecVersion returns V1 for decentralized_identifier prefix`() {
        val params = mapOf<String, Any>(
            "client_id" to "decentralized_identifier:did:web:example.com",
            "request_uri" to "https://example.com/request"
        )
        val result = findSpecVersionUsingClientId(
            clientId = "decentralized_identifier:did:web:example.com",
            clientIdPrefix = ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value,
            trustedVerifiers = emptyList()
        )
        assertEquals(SpecVersion.V1, result)
    }

    @Test
    fun `findSpecVersion returns trustedVerifier specVersion for pre-registered when verifier found`() {
        val verifiers = listOf(
            Verifier("my-client", listOf("https://example.com/response"), specVersion = SpecVersion.DRAFT_23)
        )
        val params = mapOf<String, Any>("client_id" to "my-client")
        val result = findSpecVersionUsingClientId(
            clientId = "my-client",
            clientIdPrefix = ClientIdPrefix.PRE_REGISTERED.value,
            trustedVerifiers = verifiers
        )
        assertEquals(SpecVersion.DRAFT_23, result)
    }

    @Test
    fun `findSpecVersion returns V1 for pre-registered when verifier not found in trustedVerifiers`() {
        val verifiers = listOf(
            Verifier("other-client", listOf("https://example.com/response"))
        )
        val params = mapOf<String, Any>(
            "client_id" to "unknown-client",
            "request_uri" to "https://example.com/request"
        )
        val result = findSpecVersionUsingClientId(
            clientId = "unknown-client",
            clientIdPrefix = ClientIdPrefix.PRE_REGISTERED.value,
            trustedVerifiers = verifiers
        )
        assertEquals(SpecVersion.V1, result)
    }

    @Test
    fun `findSpecVersion falls back to v1 for unknown prefix`() {
        val params = mapOf<String, Any>(
            "client_id" to "custom:something",
            "presentation_definition" to "{}"
        )
        val result = findSpecVersionUsingClientId(
            clientId = "custom:something",
            clientIdPrefix = "custom",
            trustedVerifiers = emptyList()
        )
        assertEquals(SpecVersion.V1, result)
    }

    private val walletNonce = "wallet-nonce"

    @Test
    fun `selects the pre-registered handler for a bare client_id`() {
        assertIs<PreRegisteredSchemeAuthorizationRequestHandler>(handlerFor("verifier-1"))
    }

    @Test
    fun `selects the redirect uri handler for a redirect_uri client_id`() {
        assertIs<RedirectUriPrefixAuthorizationRequestHandler>(
            handlerFor("redirect_uri:https://verifier.example/response")
        )
    }

    @Test
    fun `selects the decentralized identifier handler for a did client_id`() {
        assertIs<DecentralizedIdentifierPrefixAuthorizationRequestHandler>(
            handlerFor("did:example:verifier")
        )
    }

    @Test
    fun `selects the decentralized identifier handler for the decentralized_identifier prefix`() {
        assertIs<DecentralizedIdentifierPrefixAuthorizationRequestHandler>(
            handlerFor("decentralized_identifier:did:example:verifier")
        )
    }

    @Test
    fun `falls back to the pre-registered handler for an unrecognised prefix`() {
        assertIs<PreRegisteredSchemeAuthorizationRequestHandler>(
            handlerFor("unknown_prefix:verifier-1")
        )
    }

    @Test
    fun `requires a client_id when selecting a handler`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            getAuthorizationRequestHandler(mutableMapOf(), WalletConfig(), {}, walletNonce)
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Missing Input: client_id param is required",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `carries the resolved spec version onto the handler`() {
        val walletConfig = WalletConfig(
            trustedVerifiers = listOf(
                Verifier(
                    clientId = "verifier-1",
                    responseUris = listOf("https://verifier.example/response"),
                    specVersion = SpecVersion.DRAFT_23
                )
            )
        )

        val handler = getAuthorizationRequestHandler(
            mutableMapOf("client_id" to "verifier-1"),
            walletConfig,
            {},
            walletNonce
        )

        assertEquals(SpecVersion.DRAFT_23, handler.specVersion)
    }

    @Test
    fun `extracts and url-decodes query parameters`() {
        val params = extractQueryParameters(
            "openid4vp://authorize?client_id=verifier-1&nonce=abc%20123"
        )

        assertEquals(2, params.size)
        assertEquals("verifier-1", params["client_id"])
        assertEquals("abc 123", params["nonce"])
    }

    @Test
    fun `keeps a literal plus in a query parameter value`() {
        val params = extractQueryParameters(
            "openid4vp://authorize?client_id=verifier-1&vp_format=dc+sd-jwt"
        )

        assertEquals("dc+sd-jwt", params["vp_format"])
    }

    @Test
    fun `decodes a percent encoded plus in a query parameter value`() {
        val params = extractQueryParameters(
            "openid4vp://authorize?client_id=verifier-1&vp_format=dc%2Bsd-jwt"
        )

        assertEquals("dc+sd-jwt", params["vp_format"])
    }

    @Test
    fun `rejects a uri with no query parameters`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidQueryParams> {
            extractQueryParameters("openid4vp://authorize")
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertTrue(exception.message.contains("No Query params in the URI"))
    }

    @Test
    fun `rejects a query parameter without a value`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidQueryParams> {
            extractQueryParameters("openid4vp://authorize?client_id")
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertTrue(
            exception.message.startsWith(
                "Exception occurred when extracting the query params from Authorization Request"
            )
        )
    }

    @Test
    fun `rejects a malformed uri`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidQueryParams> {
            extractQueryParameters("not a uri at all")
        }
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
        assertTrue(
            exception.message.startsWith(
                "Exception occurred when extracting the query params from Authorization Request"
            )
        )
    }

    @Test
    fun `accepts matching client ids across the request and request object`() {
        validateAuthorizationRequestObjectAndParameters(
            mapOf("client_id" to "verifier-1"),
            mapOf("client_id" to "verifier-1"),
            "test"
        )
    }

    @Test
    fun `rejects mismatching client ids across the request and request object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MismatchingClientIDInRequest> {
            validateAuthorizationRequestObjectAndParameters(
                mapOf("client_id" to "verifier-1"),
                mapOf("client_id" to "verifier-2"),
                "test"
            )
        }
        assertOpenId4VPException(
            exception = exception,
            expectedMessage = "Client Id mismatch in Authorization Request parameter and the Request Object",
            expectedErrorCode = OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `accepts a wallet nonce echoed back by the verifier`() {
        validateWalletNonce(mapOf("wallet_nonce" to walletNonce), walletNonce)
    }

    @Test
    fun `rejects a wallet nonce the verifier did not echo back`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            validateWalletNonce(mapOf("wallet_nonce" to "other"), walletNonce)
        }
        assertEquals(
            "wallet_nonce provided in the authorization request is not the same as shared by wallet",
            exception.message
        )
    }

    @Test
    fun `accepts the supported response type`() {
        validateResponseTypeSupported("vp_token")
    }

    @Test
    fun `rejects an unsupported response type`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            validateResponseTypeSupported("id_token")
        }
        assertEquals("Response type id_token is not supported", exception.message)
    }

    @Test
    fun `accepts a wallet declaring request object signing algorithms`() {
        validateRequestObjectSigningAlgSupported(
            WalletConfig(requestObjectSigningAlgValuesSupported = listOf(SignatureAlgorithm.EdDSA))
        )
    }

    @Test
    fun `rejects a wallet declaring no request object signing algorithms`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            validateRequestObjectSigningAlgSupported(
                WalletConfig(requestObjectSigningAlgValuesSupported = null)
            )
        }
        assertEquals(
            "request_object_signing_alg_values_supported is not present in wallet metadata",
            exception.message
        )

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            validateRequestObjectSigningAlgSupported(
                WalletConfig(requestObjectSigningAlgValuesSupported = emptyList())
            )
        }
    }

    @Test
    fun `resolves the spec version without consulting the trusted verifier list`() {
        val version = findSpecVersionUsingClientId(
            clientId = "verifier-1",
            clientIdPrefix = "pre-registered",
            trustedVerifiers = listOf(
                Verifier(
                    clientId = "verifier-1",
                    responseUris = listOf("https://verifier.example/response"),
                    specVersion = SpecVersion.DRAFT_23
                )
            ),
            checkSpecVersionInPreRegisteredList = false
        )

        assertEquals(SpecVersion.V1, version)
    }

    private fun handlerFor(clientId: String) = getAuthorizationRequestHandler(
        mutableMapOf("client_id" to clientId),
        WalletConfig(),
        {},
        walletNonce
    )
}
