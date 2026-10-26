package io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.types

import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.authorizationRequest.authorizationRequestHandler.ClientIdPrefixBasedAuthorizationRequestHandler
import io.mosip.openID4VP.authorizationRequest.extractClientIdPartOnly
import io.mosip.openID4VP.authorizationRequest.validateRequestObjectSigningAlgSupported
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.ClientIdScheme
import io.mosip.openID4VP.constants.SignatureAlgorithm
import io.mosip.openID4VP.constants.SpecVersion
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import java.security.PublicKey

private val className = DecentralizedIdentifierPrefixAuthorizationRequestHandler::class.simpleName!!

class DecentralizedIdentifierPrefixAuthorizationRequestHandler(
    clientId: String,
    specVersion: SpecVersion,
    authorizationRequestParameters: MutableMap<String, Any>,
    walletConfig: WalletConfig,
    setResponseDispatchInfo: (ResponseDispatchInfo) -> Unit,
    walletNonce: String,
) : ClientIdPrefixBasedAuthorizationRequestHandler(
    clientId,
    specVersion,
    authorizationRequestParameters,
    walletConfig,
    setResponseDispatchInfo,
    walletNonce
) {
    override fun isSignedRequestSupported(): Boolean {
        return true
    }

    override fun isUnsignedRequestSupported(): Boolean {
        return false
    }

    override fun clientIdPrefix(): String {
        return ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value
    }

    override fun confirmSpecVersionIdentifiedFromRequest(): Boolean {
        return if (specVersion == SpecVersion.DRAFT_23) {
            clientId.startsWith(ClientIdScheme.DID.value)
        } else {
            clientId.startsWith(ClientIdPrefix.DECENTRALIZED_IDENTIFIER.value)
        }
    }

    override fun extractPublicKey(algorithm: SignatureAlgorithm, jwsHeader: Map<String, Any>): PublicKey {
        val kid = jwsHeader["kid"] as? String
        val didUrl = when (specVersion) {
            SpecVersion.DRAFT_23 -> clientId
            SpecVersion.V1 -> extractClientIdPartOnly(authorizationRequestParameters)
        }
        if (kid.isNullOrEmpty()) {
            throw OpenID4VPExceptions.InvalidData(
                "keyId is required to extract public key in decentralized_identifier client_id_prefix",
                className,
                OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT
            )
        }
        return DidPublicKeyResolver().resolve(didUrl, kid)
    }

    override fun getWalletMetadata(walletConfig: WalletConfig): Map<String, Any> {
        validateRequestObjectSigningAlgSupported(walletConfig)
        return walletConfig.toWalletMetadata(specVersion)
    }
}
