package io.mosip.openID4VP.responseModeHandler

import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import io.mosip.openID4VP.constants.EncryptionAlgorithm
import io.mosip.openID4VP.constants.EncryptionMethod

data class ResponseDispatchInfo(
    val responseMode: String,
    val nonce: String?,
    val walletNonce: String?,
    val state: String?,
    val clientId: String,
    val responseUrl: String,
    val responseEncryptionSpecification: ResponseEncryptionSpecification? = null
) : java.io.Serializable

data class ResponseEncryptionSpecification(
    val keyEncryptionAlg: EncryptionAlgorithm,
    val contentEncryptionAlg: EncryptionMethod,
    val verifierPublicKey: Jwk
) : java.io.Serializable
