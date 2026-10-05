package io.mosip.openID4VP.authorizationResponse

import io.mosip.openID4VP.OpenID4VP
import io.mosip.openID4VP.authorizationRequest.AuthorizationPresentationExchangeRequest
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequest
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.DescriptorMap
import io.mosip.openID4VP.authorizationResponse.presentationSubmission.PresentationSubmission
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.ldp.UnsignedLdpVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.mdoc.UnsignedMdocVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.types.sdJwt.UnsignedSdJwtVPTokenBuilder
import io.mosip.openID4VP.authorizationResponse.vpToken.VPToken
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenFactory
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenArray
import io.mosip.openID4VP.authorizationResponse.vpToken.VPTokenType.VPTokenElement
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.UUIDGenerator
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.constants.ResponseType
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.openID4VP.responseModeHandler.ResponseModeBasedHandlerFactory
import io.mosip.openID4VP.verifier.VerifierResponse
import io.mosip.openID4VP.wallet.Credential
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.jsonPrimitive

private val className = AuthorizationResponseHandler::class.java.simpleName

internal class AuthorizationResponseHandler(
    private val walletConfig: WalletConfig
) : java.io.Serializable {
    private lateinit var unsignedVPTokenResults: Map<FormatType, Pair<Map<String, Any>, List<UnsignedVPToken>>>
    private lateinit var walletNonce: String
    internal lateinit var formatToCredentialInputDescriptorMapping: Map<FormatType, List<CredentialInputDescriptorMapping>>
    internal var dcqlCredentialMappings: List<CredentialToCredentialQueryIdMapping> = emptyList()

    internal fun constructUnsignedVPToken(
        selectedCredentials: Map<String, List<Credential>>,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        nonce: String
    ): List<UnsignedVPToken> {
        try {
            val unsupportedFormats = selectedCredentials.values.flatten()
                .map { it.format }
                .filterNot { it == FormatType.MSO_MDOC || it == FormatType.DC_SD_JWT || it == FormatType.VC_SD_JWT || it == FormatType.LDP_VC }
                .distinct()
            if (unsupportedFormats.isNotEmpty()) {
                throw OpenID4VPExceptions.InvalidData(
                    "Unsigned VP token construction supports only SD-JWT, mdoc, and LDP credentials. Unsupported formats: ${unsupportedFormats.joinToString { it.value }}",
                    className
                )
            }

            val allCredentials = selectedCredentials.values.flatten()
            if (allCredentials.isEmpty()) {
                throw OpenID4VPExceptions.InvalidData(
                    "Empty credentials list - The Wallet did not have the requested Credentials to satisfy the Authorization Request.",
                    className
                )
            }

            walletNonce = nonce

            return SpecVersionHandler.from(authorizationRequest).createUnsignedVPToken(
                credentialsMap = selectedCredentials,
                authorizationRequest = authorizationRequest,
                responseUri = responseUri,
                walletNonce = nonce,
                handler = this
            )
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.VerifiablePresentationConstructionFailure(exception, className)
        }
    }

    private fun resolveError(exception: Exception): OpenID4VPExceptions =
        exception as? OpenID4VPExceptions ?: OpenID4VPExceptions.GenericFailure(
            message = exception.message ?: "Unknown internal error",
            className = OpenID4VP::class.simpleName.orEmpty()
        )

    internal fun constructAuthorizationErrorResponse(
        dispatchInfo: ResponseDispatchInfo?,
        exception: Exception,
        walletNonce: String,
        authorizationRequest: AuthorizationRequest? = null
    ): Map<String, Any> {
        this.walletNonce = walletNonce
        val resolvedError = resolveError(exception)
        return try {
            val dispatch = dispatchInfo ?: throw OpenID4VPExceptions.ErrorDispatchFailure(
                message = "Response dispatch details are not set. Cannot send error to verifier.",
                className = className
            )
            val authorizationErrorResponse = resolvedError.toAuthorizationErrorResponse(dispatch.state)
            ResponseModeBasedHandlerFactory.get(dispatch.responseMode)
                .getAuthorizationErrorResponse(dispatch, authorizationErrorResponse, authorizationRequest)
        } catch (error: Exception) {
            OpenID4VPExceptions.error(error.message ?: error.toString(), className)
            mapOf(
                "error" to "invalid_request",
                "error_description" to (error.message ?: "Unknown internal error")
            )
        }
    }

    internal fun sendAuthorizationError(
        dispatchInfo: ResponseDispatchInfo?,
        authorizationRequest: AuthorizationRequest?,
        exception: Exception
    ): VerifierResponse {
        val dispatch = dispatchInfo ?: throw OpenID4VPExceptions.ErrorDispatchFailure(
            message = "Response dispatch details are not set. Cannot send error to verifier.",
            className = className
        )
        val resolvedError = resolveError(exception)
        try {
            val authorizationErrorResponse = resolvedError.toAuthorizationErrorResponse(dispatch.state)
            val networkResponse = ResponseModeBasedHandlerFactory.get(dispatch.responseMode)
                .sendAuthorizationError(dispatch, authorizationErrorResponse, authorizationRequest)
            val verifierResponse = toVerifierResponse(networkResponse)
            (exception as? OpenID4VPExceptions)?.setVerifierResponse(verifierResponse)
            return verifierResponse
        } catch (err: Exception) {
            throw OpenID4VPExceptions.ErrorDispatchFailure(
                message = "Failed to send error to verifier: ${err.message}",
                className = className
            )
        }
    }

    internal fun constructVPResponse(
        vpTokenSigningResults: List<VPTokenSigningResult>,
        authorizationRequest: AuthorizationRequest,
        dispatchInfo: ResponseDispatchInfo?
    ): Map<String, String> {
        try {
            val authorizationResponse = createAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = reconstructSigningResults(vpTokenSigningResults)
            )
            val dispatch = dispatchInfo ?: throw OpenID4VPExceptions.ErrorDispatchFailure(
                message = "Response dispatch details are not set. Cannot construct VP response.",
                className = className
            )
            return ResponseModeBasedHandlerFactory.get(dispatch.responseMode)
                .getAuthorizationResponse(dispatch, authorizationResponse, authorizationRequest)
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.AuthorizationResponseConstructionFailure(exception, className)
        }
    }

    internal fun constructAndSendAuthorizationResponseToVerifier(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: List<VPTokenSigningResult>,
        dispatchInfo: ResponseDispatchInfo?
    ): VerifierResponse {
        val dispatch = dispatchInfo ?: throw OpenID4VPExceptions.ErrorDispatchFailure(
            message = "Response dispatch details are not set. Cannot send authorization response to verifier.",
            className = className
        )
        val authorizationResponse: AuthorizationResponse = try {
            createAuthorizationResponse(
                authorizationRequest = authorizationRequest,
                vpTokenSigningResults = reconstructSigningResults(vpTokenSigningResults)
            )
        } catch (exception: Exception) {
            throw OpenID4VPExceptions.AuthorizationResponseConstructionFailure(exception, className)
        }
        val networkResponse = ResponseModeBasedHandlerFactory.get(dispatch.responseMode)
            .sendAuthorizationResponse(dispatch, authorizationResponse, authorizationRequest)
        return toVerifierResponse(networkResponse)
    }


    private fun createAuthorizationResponse(
        authorizationRequest: AuthorizationRequest,
        vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
    ): AuthorizationResponse {
        when (authorizationRequest.responseType) {
            ResponseType.VP_TOKEN.value -> {
                return SpecVersionHandler.from(authorizationRequest).createVPTokenResponse(
                    authorizationRequest = authorizationRequest,
                    vpTokenSigningResults = vpTokenSigningResults,
                    handler = this
                )
            }

            else -> throw OpenID4VPExceptions.InvalidData(
                "Provided response_type - ${authorizationRequest.responseType} is not supported",
                className
            )
        }
    }

    private fun reconstructSigningResults(
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): Map<FormatType, List<VPTokenSigningResult>> {
        return constructSigningResults(
            unsignedVPTokenResults = unsignedVPTokenResults,
            signingResults = vpTokenSigningResults,
            className = className
        )
    }

    internal fun createVPTokenAndPresentationSubmission(
        vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
        authorizationRequest: AuthorizationRequest,
        formatToCredentialInputDescriptorMapping: Map<FormatType, List<CredentialInputDescriptorMapping>>
    ): Pair<VPTokenType, PresentationSubmission> {
        val finalVpTokens: MutableList<VPToken> = mutableListOf()
        val finalDescriptorMappings: MutableList<DescriptorMap> = mutableListOf()
        var rootIndex = 0

        formatToCredentialInputDescriptorMapping.forEach { (credentialFormat, credentialInputDescriptorMappings) ->
            val (vpTokenSigningResultsForFormat, unsignedVPTokenResult) = getData(vpTokenSigningResults, credentialFormat)
            val vpTokenBuilder = VPTokenFactory.getVPTokenBuilder(credentialFormat)

            val (vpTokens, descriptorMaps, nextRootIndex) = vpTokenBuilder.build(
                credentialInputDescriptorMappings,
                unsignedVPTokenResult,
                vpTokenSigningResultsForFormat,
                rootIndex
            )
            finalVpTokens.addAll(vpTokens)
            finalDescriptorMappings.addAll(descriptorMaps)

            rootIndex = nextRootIndex
        }

        val vpToken = (finalVpTokens.takeIf { it.size == 1 }
            ?.let { VPTokenElement(it[0]) }
            ?: VPTokenArray(finalVpTokens))

        sanitizeDescriptorMap(finalDescriptorMappings, finalVpTokens.size == 1)
        val definitionId = (authorizationRequest as? AuthorizationPresentationExchangeRequest)?.presentationDefinition?.id ?: ""
        val presentationSubmission = PresentationSubmission(
            id = UUIDGenerator.generateUUID(),
            definitionId = definitionId,
            descriptorMap = finalDescriptorMappings,
        )

        return Pair(vpToken, presentationSubmission)
    }

    internal fun createDcqlVPToken(
        vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
        dcqlCredentialMappings: List<CredentialToCredentialQueryIdMapping>
    ): Map<String, List<VPToken>> {
        val credentialMappingsByFormat = dcqlCredentialMappings.groupBy { it.format }
        val finalVpTokens = mutableMapOf<String, MutableList<VPToken>>()

        for ((credentialFormat, mappings) in credentialMappingsByFormat) {
            // Allow empty signing results for formats where no holder binding is required
            val (vpTokenSigningResultsForFormat, unsignedVPTokenResult) = getData(
                vpTokenSigningResults,
                credentialFormat
            )

            val vpTokenBuilder = VPTokenFactory.getVPTokenBuilder(credentialFormat)
            val vpTokenResult = vpTokenBuilder.build(
                credentialToCredentialQueryIdMappings = mappings,
                unsignedVPTokenResult = unsignedVPTokenResult,
                vpTokenSigningResults = vpTokenSigningResultsForFormat
            )

            for ((key, newValue) in vpTokenResult) {
                finalVpTokens.getOrPut(key) { mutableListOf() }.addAll(newValue)
            }
        }

        return finalVpTokens
    }

    private fun getData(
        vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
        credentialFormat: FormatType
    ): Pair<List<VPTokenSigningResult>, Pair<Map<String, Any>, List<UnsignedVPToken>>> {
        val vpTokenSigningResultsForFormat =
            vpTokenSigningResults[credentialFormat] ?: emptyList()
        val unsignedVPTokenResult = unsignedVPTokenResults[credentialFormat]
            ?: throw OpenID4VPExceptions.InvalidData(
                "unable to find the related credential format - $credentialFormat in the unsignedVPTokenResults map",
                className
            )
        return Pair(vpTokenSigningResultsForFormat, unsignedVPTokenResult)
    }

    private fun sanitizeDescriptorMap(
        descriptorMaps: MutableList<DescriptorMap>,
        isSingleVPToken: Boolean
    ) {
        if (isSingleVPToken) {
            descriptorMaps.forEach { descriptorMap ->
                val updatedRootPath = descriptorMap.path.replace(Regex("""\[\d+]"""), "")
                val updatedDescriptorMap = descriptorMap.copy(
                    path = updatedRootPath,
                    pathNested = descriptorMap.pathNested
                )
                descriptorMaps[descriptorMaps.indexOf(descriptorMap)] = updatedDescriptorMap
            }
        }
    }

    internal fun createUnsignedVPTokenForPresentationExchange(
        credentialsMap: Map<String, List<Credential>>,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        walletNonce: String
    ): List<UnsignedVPToken> {
        val specVersion = SpecVersion.DRAFT_23
        val formatToMappings = mutableMapOf<FormatType, MutableList<CredentialInputDescriptorMapping>>()
        for ((inputDescriptorId, credentials) in credentialsMap) {
            for (credential in credentials) {
                formatToMappings.getOrPut(credential.format) { mutableListOf() }
                    .add(CredentialInputDescriptorMapping(
                        format = credential.format,
                        credential = credential.data,
                        inputDescriptorId = inputDescriptorId
                    ))
            }
        }
        this.formatToCredentialInputDescriptorMapping = formatToMappings

        val results = mutableMapOf<FormatType, Pair<Map<String, Any>, List<UnsignedVPToken>>>()
        for ((format, mappings) in formatToMappings) {
            results[format] = when (format) {
                FormatType.LDP_VC -> UnsignedLdpVPTokenBuilder(authorizationRequest, specVersion, UUIDGenerator.generateUUID(), walletConfig).build(mappings)
                FormatType.MSO_MDOC -> UnsignedMdocVPTokenBuilder(authorizationRequest, specVersion, responseUri, walletNonce, walletConfig).build(mappings)
                FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> UnsignedSdJwtVPTokenBuilder(authorizationRequest, specVersion, walletConfig).build(mappings)
            }
        }
        this.unsignedVPTokenResults = results

        return unsignedVPTokenResults.values.flatMap { it.second }
    }

    internal fun createUnsignedVPTokenForDcqlRequest(
        credentialsMap: Map<String, List<Credential>>,
        authorizationRequest: AuthorizationRequest,
        responseUri: String,
        walletNonce: String
    ): List<UnsignedVPToken> {
        val specVersion = SpecVersion.V1
        dcqlCredentialMappings = credentialsMap.flatMap { (credentialQueryId, credentials) ->
            credentials.map { CredentialToCredentialQueryIdMapping(it.format, it.data, credentialQueryId) }
        }
        val dcqlMappingsByFormat = dcqlCredentialMappings.groupBy { it.format }
        val results = mutableMapOf<FormatType, Pair<Map<String, Any>, List<UnsignedVPToken>>>()
        for ((format, mappings) in dcqlMappingsByFormat) {
            val mutableMappings = mappings.toMutableList()
            results[format] = when (format) {
                FormatType.LDP_VC -> UnsignedLdpVPTokenBuilder(authorizationRequest, specVersion, UUIDGenerator.generateUUID(), walletConfig).build(mutableMappings)
                FormatType.MSO_MDOC -> UnsignedMdocVPTokenBuilder(authorizationRequest, specVersion, responseUri, walletNonce, walletConfig).build(mutableMappings)
                FormatType.DC_SD_JWT, FormatType.VC_SD_JWT -> UnsignedSdJwtVPTokenBuilder(authorizationRequest, specVersion, walletConfig).build(mutableMappings)
            }
        }
        this.unsignedVPTokenResults = results

        return unsignedVPTokenResults.values.flatMap { it.second }
    }



    private fun toVerifierResponse(networkResponse: NetworkResponse): VerifierResponse {
        val redirectUriKey = "redirect_uri"

        val jsonElement = runCatching { Json.parseToJsonElement(networkResponse.body) }.getOrNull()
        val jsonObject = jsonElement as? JsonObject
        val redirectUri =
            runCatching { jsonObject?.get(redirectUriKey)?.jsonPrimitive?.contentOrNull }.getOrNull()
        val additionalParams = jsonObject?.toMutableMap()?.apply { remove(redirectUriKey) }
            ?.let { Json.encodeToString(JsonObject.serializer(), JsonObject(it)) }
            ?: networkResponse.body

        return VerifierResponse(
            networkResponse.statusCode,
            redirectUri,
            additionalParams,
            networkResponse.headers,
            networkResponse.body
        )
    }

    private sealed class SpecVersionHandler {
        object Draft23 : SpecVersionHandler()
        object SpecV1 : SpecVersionHandler()

        companion object {
            fun from(authorizationRequest: AuthorizationRequest): SpecVersionHandler =
                if (authorizationRequest is AuthorizationPresentationExchangeRequest) Draft23 else SpecV1
        }

        fun createUnsignedVPToken(
            credentialsMap: Map<String, List<Credential>>,
            authorizationRequest: AuthorizationRequest,
            responseUri: String,
            walletNonce: String,
            handler: AuthorizationResponseHandler
        ): List<UnsignedVPToken> = when (this) {
            is Draft23 -> handler.createUnsignedVPTokenForPresentationExchange(credentialsMap, authorizationRequest, responseUri, walletNonce)
            is SpecV1 -> handler.createUnsignedVPTokenForDcqlRequest(credentialsMap, authorizationRequest, responseUri, walletNonce)
        }

        fun createVPTokenResponse(
            authorizationRequest: AuthorizationRequest,
            vpTokenSigningResults: Map<FormatType, List<VPTokenSigningResult>>,
            handler: AuthorizationResponseHandler
        ): AuthorizationResponse {
            return when (this) {
                is Draft23 -> {
                    val (vpToken, presentationSubmission) = handler.createVPTokenAndPresentationSubmission(
                        vpTokenSigningResults,
                        authorizationRequest,
                        handler.formatToCredentialInputDescriptorMapping
                    )
                    AuthorizationResponse.PresentationExchange(
                        presentationSubmission = presentationSubmission,
                        vpToken = vpToken,
                        state = authorizationRequest.state
                    )
                }

                is SpecV1 -> {
                    val vpTokensResult = handler.createDcqlVPToken(
                        vpTokenSigningResults = vpTokenSigningResults,
                        dcqlCredentialMappings = handler.dcqlCredentialMappings
                    )
                    AuthorizationResponse.Dcql(
                        vpToken = vpTokensResult,
                        state = authorizationRequest.state
                    )
                }
            }
        }
    }
}
