package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdPrefixBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types.*
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import java.net.URI
import java.net.URLDecoder

private val className = AuthorizationRequest::class.simpleName!!

fun getAuthorizationRequestHandler(
    authorizationRequestParameters: MutableMap<String, Any>,
    walletConfig: WalletConfig,
    setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit,
    walletNonce: String
): ClientIdPrefixBasedAuthorizationRequestHandler {
    validate(CLIENT_ID.value, getStringValue(authorizationRequestParameters, CLIENT_ID.value), className)
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val clientIdPrefix = extractClientIdPrefix(authorizationRequestParameters)
    val specVersion = findSpecVersionUsingClientId(
        clientId,
        clientIdPrefix,
        walletConfig.trustedVerifiers,
        walletConfig.validateTrustedVerifier
    )

    return when (clientIdPrefix) {
        ClientIdPrefix.PRE_REGISTERED.value -> PreRegisteredSchemeAuthorizationRequestHandler(
            clientId = clientId,
            specVersion = specVersion,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )
        ClientIdPrefix.REDIRECT_URI.value -> RedirectUriPrefixAuthorizationRequestHandler(
            clientId = clientId,
            specVersion = specVersion,
            authorizationRequestParameters = authorizationRequestParameters,
            walletConfig = walletConfig,
            setResponseDispatchInfo = setResponseDispatchInfo,
            walletNonce = walletNonce
        )
        ClientIdScheme.DID.value, ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value ->
            DecentralizedIdentifierPrefixAuthorizationRequestHandler(
                clientId = clientId,
                specVersion = specVersion,
                authorizationRequestParameters = authorizationRequestParameters,
                walletConfig = walletConfig,
                setResponseDispatchInfo = setResponseDispatchInfo,
                walletNonce = walletNonce
            )
        else -> {
            PreRegisteredSchemeAuthorizationRequestHandler(
                clientId = clientId,
                specVersion = specVersion,
                authorizationRequestParameters = authorizationRequestParameters,
                walletConfig = walletConfig,
                setResponseDispatchInfo = setResponseDispatchInfo,
                walletNonce = walletNonce
            )
        }
    }
}

fun extractQueryParameters(query: String): Map<String, Any> {
    try {
        val uri = URI(query)
        val queryParams: Map<String, String> = uri.rawQuery?.split("&")?.associate {
            val (key, value) = it.split("=")
            key to percentDecode(value)
        } ?: throw OpenID4VPExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : No Query params in the URI", className)

        return queryParams
    } catch (exception: Exception) {
        throw OpenID4VPExceptions.InvalidQueryParams("Exception occurred when extracting the query params from Authorization Request : ${exception.message}", className)
    }
}

private fun percentDecode(value: String): String =
    URLDecoder.decode(value.replace("+", "%2B"), "UTF-8")

fun validateAuthorizationRequestObjectAndParameters(
    params: Map<String, Any>,
    requestObject: Map<String, Any>,
    className: String,
) {
    if (params[CLIENT_ID.value] != requestObject[CLIENT_ID.value]) {
        throw OpenID4VPExceptions.MismatchingClientIDInRequest(className)
    }
}

fun extractClientIdPrefix(authorizationRequestParameters: Map<String, Any>): String {
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!

    val components = clientId.split(":", limit = 2)

    if (components.size > 1) {
        val prefix = components[0]
        if (prefix == ClientIdScheme.DID.value) {
            return ClientIdScheme.DID.value
        }
        if (ClientIdPrefix.fromValue(prefix) != null) {
            return prefix
        }
        // Treat unrecognized prefixes as pre-registered and validate against trusted verifier list.
        return ClientIdPrefix.PRE_REGISTERED.value
    }

    return ClientIdPrefix.PRE_REGISTERED.value
}

fun extractClientIdPartOnly(authorizationRequestParameters: Map<String, Any>): String {
    val clientId = getStringValue(authorizationRequestParameters, CLIENT_ID.value)!!
    val components = clientId.split(":", limit = 2)
    if (components.size > 1) {
        val prefix = components[0]
        if (prefix == ClientIdScheme.DID.value) {
            return clientId
        }
        if (ClientIdPrefix.fromValue(prefix) != null) {
            return components[1]
        }
        return clientId
    }
    return clientId
}

fun findSpecVersionUsingClientId(
    clientId: String,
    clientIdPrefix: String,
    trustedVerifiers: List<Verifier>,
    checkSpecVersionInPreRegisteredList: Boolean = true
): SpecVersion {
    return when (clientIdPrefix) {
        ClientIdScheme.DID.value -> SpecVersion.DRAFT_23
        ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value -> SpecVersion.V1
        ClientIdPrefix.PRE_REGISTERED.value -> {
            if (checkSpecVersionInPreRegisteredList) {
                trustedVerifiers.firstOrNull { it.clientId == clientId }?.specVersion ?: SpecVersion.V1
            } else {
                SpecVersion.V1
            }
        }
        else -> SpecVersion.V1
    }
}

fun findSpecVersionUsingRequestParameters(authorizationRequestParameters: Map<String, Any>): SpecVersion {
    if (authorizationRequestParameters.containsKey(DCQL_QUERY.value)) {
        return SpecVersion.V1
    }
    return SpecVersion.DRAFT_23

}

fun validateRequestObjectSigningAlgSupported(walletConfig: WalletConfig) {
    if (walletConfig.requestObjectSigningAlgValuesSupported.isNullOrEmpty()) {
        throw OpenID4VPExceptions.InvalidData(
            "request_object_signing_alg_values_supported is not present in wallet metadata",
            className
        )
    }
}

fun validateWalletNonce(requestUriResponse: Map<String, Any>, walletNonce: String) {
    if (requestUriResponse[WALLET_NONCE.value] != walletNonce) {
        throw OpenID4VPExceptions.InvalidData("wallet_nonce provided in the authorization request is not the same as shared by wallet", className)
    }
}

fun validateResponseTypeSupported(responseType: String) {
    ResponseType.entries.find { it.value == responseType } ?: throw OpenID4VPExceptions.InvalidData(
        "Response type $responseType is not supported",
        className
    )
}
