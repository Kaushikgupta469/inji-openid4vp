package io.mosip.openID4VP.authorizationRequest

import com.fasterxml.jackson.annotation.JsonProperty
import io.mosip.openID4VP.constants.ProofType

sealed interface VPFormatSupported : java.io.Serializable {
    fun toAlgValuesSupported(): List<String>?
}

data class LdpVpFormatSupported(
    @JsonProperty("proof_type_values")
    val proofTypeValues: List<ProofType>? = listOf(ProofType.Ed25519Signature2020, ProofType.JsonWebSignature2020),

    @JsonProperty("cryptosuite_values")
    val cryptoSuiteValues: List<String>? = null
) : VPFormatSupported {
    override fun toAlgValuesSupported(): List<String>? {
        return proofTypeValues?.map { it.value }
    }
}

data class MsoMdocVpFormatSupported(
    @JsonProperty("issuerauth_alg_values")
    val issuerAuthAlgValues: List<Int>? = null,

    @JsonProperty("deviceauth_alg_values")
    val deviceAuthAlgValues: List<Int>? = null
) : VPFormatSupported {
    private val algorithmValueNameMap = mapOf(
        -7 to "ES256",
        -9 to "ESP256"
    )

    override fun toAlgValuesSupported(): List<String>? {
        return deviceAuthAlgValues?.mapNotNull { algorithmValueNameMap[it] }
    }
}

data class SdJwtVpFormatSupported(
    @JsonProperty("sd-jwt_alg_values")
    val sdJwtAlgValues: List<String>? = null,

    @JsonProperty("kb-jwt_alg_values")
    val kbJwtAlgValues: List<String>? = null
) : VPFormatSupported {
    override fun toAlgValuesSupported(): List<String>? {
        return kbJwtAlgValues
    }
}
