package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_MODE
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.RESPONSE_URI
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdPrefixBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.extractClientIdPartOnly
import io.mosip.openID4VP.authorizationRequest.validateRequestObjectSigningAlgSupported
import io.mosip.openID4VP.common.getStringValue
import io.mosip.openID4VP.common.validate
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.ResponseMode.DIRECT_POST
import io.mosip.openID4VP.constants.ResponseMode.DIRECT_POST_JWT
import io.mosip.openID4VP.constants.ResponseMode.IAR_POST
import io.mosip.openID4VP.constants.ResponseMode.IAR_POST_JWT
import io.mosip.openID4VP.constants.ResponseMode.IAE_POST
import io.mosip.openID4VP.constants.ResponseMode.IAE_POST_JWT
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import java.security.PublicKey
import java.util.logging.Logger

private val className = RedirectUriPrefixAuthorizationRequestHandler::class.simpleName!!

class RedirectUriPrefixAuthorizationRequestHandler(
    clientId: String,
    specVersion: SpecVersion,
    authorizationRequestParameters: MutableMap<String, Any>,
    walletConfig: WalletConfig,
    setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit,
    walletNonce: String
) : ClientIdPrefixBasedAuthorizationRequestHandler(
    clientId,
    specVersion,
    authorizationRequestParameters,
    walletConfig,
    setResponseDispatchInfo,
    walletNonce
) {

    private val logger = Logger.getLogger(className)

    override fun isSignedRequestSupported(): Boolean {
        return false
    }

    override fun isUnsignedRequestSupported(): Boolean {
        return true
    }

    override fun clientIdPrefix(): String {
        return ClientIdPrefix.REDIRECT_URI.value
    }

    override fun extractPublicKey(algorithm: SignatureAlgorithm, jwsHeader: Map<String, Any>): PublicKey {
        throw UnsupportedOperationException("Public key extraction is not supported for redirect_uri client_id_prefix")
    }

    override fun getWalletMetadata(walletConfig: WalletConfig): Map<String, Any> {
        validateRequestObjectSigningAlgSupported(walletConfig)
        return walletConfig.toWalletMetadata(specVersion, true)
    }

    override fun validateClientAuthenticity() {
        val responseMode = getStringValue(authorizationRequestParameters, RESPONSE_MODE.value) ?:
        throw OpenID4VPExceptions.MissingInput(listOf(RESPONSE_MODE.value), "", className)
         when (responseMode) {
            DIRECT_POST.value, DIRECT_POST_JWT.value -> {
                validateResponseUriMatchesClientId(authorizationRequestParameters)
            }
             IAR_POST.value, IAR_POST_JWT.value -> {
                 logger.info("IAR_POST or IAR_POST_JWT response_mode is used")
             }
             IAE_POST.value, IAE_POST_JWT.value -> {
                 logger.info("IAE_POST or IAE_POST_JWT response_mode is used")
             }
            else -> throw OpenID4VPExceptions.InvalidData("Given response_mode - $responseMode is not supported", className)
        }
    }

    private fun validateResponseUriMatchesClientId(authRequestParam: Map<String, Any>) {
        val responseUri = getStringValue(authRequestParam, RESPONSE_URI.value)

        validate(RESPONSE_URI.value, responseUri, className)

        if (authRequestParam[RESPONSE_URI.value] != extractClientIdPartOnly(authRequestParam))
            throw OpenID4VPExceptions.InvalidData(
                "${RESPONSE_URI.value} should be equal to client_id for given client_id_prefix",
                className,
                notifyVerifier = false
            )
    }
}