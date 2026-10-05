package io.mosip.openID4VP.authorizationRequest

import com.fasterxml.jackson.databind.ObjectMapper
import io.mosip.openID4VP.constants.*
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private const val className = "WalletConfig"

data class WalletConfig @JvmOverloads constructor(
    val vpFormatsSupported: Map<VPFormatType, VPFormatSupported> = getDefaultVpFormatsSupported(),
    val clientIdPrefixesSupported: List<ClientIdPrefix> = getDefaultClientIdPrefixesSupported(),
    val requestObjectSigningAlgValuesSupported: List<SignatureAlgorithm>? = getDefaultSignatureAlgorithmSupported(),
    val authorizationEncryptionAlgValuesSupported: List<EncryptionAlgorithm>? = getDefaultEncryptionAlgorithmSupported(),
    val authorizationEncryptionEncValuesSupported: List<EncryptionMethod>? = getDefaultEncryptionMethodSupported(),
    val responseTypesSupported: List<ResponseType> = getDefaultResponseTypeSupported(),
    val isPresentationDefinitionUriSupported: Boolean = true,
    val trustedVerifiers: List<Verifier> = emptyList(),
    val validateTrustedVerifier: Boolean = true
) : java.io.Serializable {
    @Suppress("UNCHECKED_CAST")
    fun toWalletMetadata(
        specVersion: SpecVersion,
        excludeSignedRequestConfig: Boolean = false
    ): Map<String, Any> {
        return try {
            val mapper = ObjectMapper()
            val walletMetadata = mutableMapOf<String, Any>()

            when (specVersion) {
                SpecVersion.V1 -> {
                    val vpFormatsEncoded = vpFormatsSupported.entries.associate { (key, value) ->
                        val formatDict = mapper.convertValue(value, Map::class.java) as Map<String, Any>
                        key.value to formatDict
                    }
                    walletMetadata["vp_formats_supported"] = vpFormatsEncoded
                    walletMetadata["client_id_prefixes_supported"] = clientIdPrefixesSupported.map { it.value }
                    requestObjectSigningAlgValuesSupported?.let {
                        walletMetadata["request_object_signing_alg_values_supported"] = it.map { alg -> alg.value }
                    }
                    authorizationEncryptionAlgValuesSupported?.let {
                        walletMetadata["authorization_encryption_alg_values_supported"] = it.map { alg -> alg.value }
                    }
                    authorizationEncryptionEncValuesSupported?.let {
                        walletMetadata["authorization_encryption_enc_values_supported"] = it.map { enc -> enc.value }
                    }
                    walletMetadata["response_types_supported"] = responseTypesSupported.map { it.value }
                }

                SpecVersion.DRAFT_23 -> {
                    val vpFormats = vpFormatsSupported.entries.associate { (key, value) ->
                        val algValues = value.toAlgValuesSupported()
                        if (algValues != null) {
                            key.value to mapOf("alg_values_supported" to algValues)
                        } else {
                            key.value to emptyMap<String, Any>()
                        }
                    }
                    walletMetadata["presentation_definition_uri_supported"] = isPresentationDefinitionUriSupported
                    walletMetadata["vp_formats_supported"] = vpFormats
                    walletMetadata["client_id_schemes_supported"] = clientIdPrefixesSupported.map { ClientIdPrefix.toClientIdScheme(it) }
                    requestObjectSigningAlgValuesSupported?.let {
                        walletMetadata["request_object_signing_alg_values_supported"] = it.map { alg -> alg.value }
                    }
                    authorizationEncryptionAlgValuesSupported?.let {
                        walletMetadata["authorization_encryption_alg_values_supported"] = it.map { alg -> alg.value }
                    }
                    authorizationEncryptionEncValuesSupported?.let {
                        walletMetadata["authorization_encryption_enc_values_supported"] = it.map { enc -> enc.value }
                    }
                    walletMetadata["response_types_supported"] = responseTypesSupported.map { it.value }
                }
            }

            if (excludeSignedRequestConfig) {
                walletMetadata.remove("request_object_signing_alg_values_supported")
            }

            walletMetadata
        } catch (e: Exception) {
            throw OpenID4VPExceptions.EncodingFailed(
                message = "Error encoding wallet metadata: ${e.message}",
                className = className
            )
        }
    }
}
