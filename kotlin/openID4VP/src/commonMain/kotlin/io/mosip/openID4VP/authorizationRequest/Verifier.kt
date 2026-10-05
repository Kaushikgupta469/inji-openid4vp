package io.mosip.openID4VP.authorizationRequest

import io.mosip.openID4VP.constants.SpecVersion

data class Verifier @JvmOverloads constructor(
    val clientId: String,
    val responseUris: List<String>,
    val jwksUri: String? = null,
    val allowUnsignedRequest: Boolean = false,
    val specVersion: SpecVersion = SpecVersion.V1
) : java.io.Serializable