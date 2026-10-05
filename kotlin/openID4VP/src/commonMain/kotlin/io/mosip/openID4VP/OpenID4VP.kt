package io.mosip.openID4VP


import io.mosip.openID4VP.authorizationRequest.*
import io.mosip.openID4VP.authorizationResponse.*
import io.mosip.openID4VP.authorizationResponse.unsignedVPToken.UnsignedVPToken
import io.mosip.openID4VP.authorizationResponse.vpTokenSigningResult.VPTokenSigningResult
import io.mosip.openID4VP.common.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo
import io.mosip.openID4VP.verifier.VerifierResponse
import io.mosip.openID4VP.wallet.Credential

class OpenID4VP @JvmOverloads constructor(
    private val traceabilityId: String,
    private val walletConfig: WalletConfig = WalletConfig()
) : java.io.Serializable {
    private var authorizationResponseHandler = AuthorizationResponseHandler(walletConfig = walletConfig)
    private var responseDispatchInfo: ResponseDispatchInfo? = null
    private var walletNonce: String = generateNonce()
    var authorizationRequest: AuthorizationRequest? = null
    private val className = OpenID4VP::class.simpleName.orEmpty()

    /** Begins the authentication by validating the incoming Authorization request */
    fun authenticateVerifier(
        urlEncodedAuthorizationRequest: String
    ): AuthorizationRequest {
        return try {
            walletNonce = generateNonce()
            authorizationRequest = null
            responseDispatchInfo = null
            authorizationResponseHandler = AuthorizationResponseHandler(walletConfig)
            val authorizationRequest =
                AuthorizationRequest.validateAndCreateAuthorizationRequest(
                    urlEncodedAuthorizationRequest,
                    walletConfig,
                    ::setResponseDispatchInfo,
                    walletNonce
                )
            this.authorizationRequest = authorizationRequest
            authorizationRequest
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    fun authenticateVerifier(
        authorizationRequest: Map<String, Any>,
    ): AuthorizationRequest {
        return try {
            walletNonce = generateNonce()
            this.authorizationRequest = null
            responseDispatchInfo = null
            authorizationResponseHandler = AuthorizationResponseHandler(walletConfig)
            val validatedAuthorizationRequest =
                AuthorizationRequest.validateAndCreateAuthorizationRequest(
                    authorizationRequest,
                    walletConfig,
                    ::setResponseDispatchInfo,
                    walletNonce
                )
            this.authorizationRequest = validatedAuthorizationRequest
            validatedAuthorizationRequest
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        }
    }

    fun constructUnsignedVPToken(
        selectedCredentials: Map<String, List<Credential>>
    ): List<UnsignedVPToken> {
        return try {
            authorizationResponseHandler.constructUnsignedVPToken(
                selectedCredentials = selectedCredentials,
                authorizationRequest = authorizationRequest!!,
                responseUri = responseDispatchInfo!!.responseUrl,
                nonce = walletNonce
            )
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        } catch (exception: Exception) {
            val wrapped = OpenID4VPExceptions.VerifiablePresentationConstructionFailure(exception, className)
            this.safeSendError(wrapped)
            throw wrapped
        }
    }

    fun constructVPResponse(vpTokenSigningResults: List<VPTokenSigningResult>): Map<String, Any> {
        return try {
            authorizationResponseHandler.constructVPResponse(
                authorizationRequest = authorizationRequest!!,
                vpTokenSigningResults = vpTokenSigningResults,
                dispatchInfo = responseDispatchInfo
            )
        } catch (exception: OpenID4VPExceptions) {
            return constructErrorInfo(exception)
        } catch (exception: Exception) {
            val wrapped = OpenID4VPExceptions.AuthorizationResponseConstructionFailure(exception, className)
            return constructErrorInfo(wrapped)
        }
    }


    /** Sends the final Authorization response to Verifier with the Verifiable Presentations as per response type
     * Returns the Verifier response as Verifier Response object
     * */
    fun sendVPResponseToVerifier(
        vpTokenSigningResults: List<VPTokenSigningResult>
    ): VerifierResponse {
        return try {
            authorizationResponseHandler.constructAndSendAuthorizationResponseToVerifier(
                authorizationRequest = authorizationRequest!!,
                vpTokenSigningResults = vpTokenSigningResults,
                dispatchInfo = responseDispatchInfo
            )
        } catch (exception: OpenID4VPExceptions) {
            this.safeSendError(exception)
            throw exception
        } catch (exception: Exception) {
            val wrapped = OpenID4VPExceptions.AuthorizationResponseConstructionFailure(exception, className)
            this.safeSendError(wrapped)
            throw wrapped
        }
    }

    fun constructErrorInfo(exception: Exception): Map<String, Any> {
        return authorizationResponseHandler.constructAuthorizationErrorResponse(
            responseDispatchInfo,
            exception,
            walletNonce,
            authorizationRequest
        )
    }

    /**
     * Sends Authorization error to the Verifier and returns the response from the Verifier.
     * The response body from Verifier response is returned as a Verifier Response object.
     */
    fun sendErrorInfoToVerifier(exception: Exception): VerifierResponse {
        return authorizationResponseHandler.sendAuthorizationError(
            responseDispatchInfo,
            authorizationRequest,
            exception
        )
    }

    private fun setResponseDispatchInfo(dispatchInfo: ResponseDispatchInfo) {
        this.responseDispatchInfo = dispatchInfo
    }

    private fun safeSendError(exception: Exception) {
        if (exception is OpenID4VPExceptions && !exception.notifyVerifier) return
        try {
            val verifierResponse = sendErrorInfoToVerifier(exception)
            (exception as? OpenID4VPExceptions)?.setVerifierResponse(verifierResponse)
        } catch (error: Exception) {
            OpenID4VPExceptions.error(error.message ?: error.localizedMessage, className)
        }
    }

}
