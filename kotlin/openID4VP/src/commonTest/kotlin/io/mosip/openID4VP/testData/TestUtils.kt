package io.mosip.openID4VP.testData

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_ID
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.CLIENT_METADATA
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.WalletConfig
import io.mosip.openID4VP.constants.ClientIdPrefix
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.JWSUtil.Companion.createJWS
import io.mosip.vercred.vcverifier.exception.PublicKeyNotFoundException
import kotlinx.serialization.json.JsonObject
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.util.encoders.Hex
import java.lang.reflect.Field
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.PublicKey
import java.security.spec.X509EncodedKeySpec
import kotlin.test.assertEquals

const val ED_DER_PUBLIC_KEY_PREFIX = "302a300506032b6570032100"
fun toJavaPublicKey(multibase: String, keyType: String): PublicKey {
    try {
        val rawPublicKeyWithHeader = io.ipfs.multibase.Base58.decode(multibase.substring(1))
        val rawPublicKey = rawPublicKeyWithHeader.copyOfRange(2, rawPublicKeyWithHeader.size)
        val publicKey = Hex.decode(ED_DER_PUBLIC_KEY_PREFIX) + rawPublicKey
        val pubKeySpec = X509EncodedKeySpec(publicKey)
        val keyFactory = KeyFactory.getInstance(keyType, BouncyCastleProvider())
        return keyFactory.generatePublic(pubKeySpec)
    } catch (e: Exception) {
        println("Error while getting public key object from Multibase: ${e.message}")
        throw PublicKeyNotFoundException("Public key object is null")
    }
}


fun setField(instance: Any, fieldName: String, value: Any?) {
    val field: Field = instance::class.java.getDeclaredField(fieldName)
    field.isAccessible = true
    field.set(instance, value)
}

fun testDispatchInfo(
    responseUrl: String = "https://mock-verifier.com/response-uri",
    responseMode: String = "direct_post",
    state: String? = "fsnC8ixCs6mWyV+00k23Qg=="
) = io.mosip.openID4VP.responseModeHandler.ResponseDispatchInfo(
    responseMode = responseMode,
    nonce = "bMHvX1HGhbh8zqlSWf/fuQ==",
    walletNonce = "VbRRB/LTxLiXmVNZuyMO8A==",
    state = state,
    clientId = "https://mock-verifier.com",
    responseUrl = responseUrl
)

fun createUrlEncodedData(
    requestParams: Map<String, String?>,
    verifierSentAuthRequestByReference: Boolean? = false,
    clientIdScheme: ClientIdPrefix,
    applicableFields: List<String>? = null,
    draftVersion: Int = 23,
): String {
    val paramList = when (verifierSentAuthRequestByReference) {
        true -> {
            if (draftVersion == 23)
                authRequestParamsByReferenceDraft23
            else
                authRequestParamsByReferenceDraft21
        }

        else -> applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    }
    val authorizationRequestParam =
        createAuthorizationRequest(paramList, requestParams, draftVersion) as Map<String, Any>

    val charset = StandardCharsets.UTF_8.toString()

    val queryString = authorizationRequestParam.entries.joinToString("&") {
        "${it.key}=${URLEncoder.encode(it.value?.toString() ?: "", charset).replace("+", "%20")}"
    }
//    val urlEncodedQueryParameters = URLEncoder.encode(queryString, charset)
    return "openid4vp://authorize?$queryString"

}

fun createAuthorizationRequestObject(
    clientIdScheme: ClientIdPrefix,
    authorizationRequestParams: Map<String, String>,
    applicableFields: List<String>? = null,
    addValidSignature: Boolean? = true,
    jwtHeader: JsonObject? = null,
    isPresentationDefinitionUriPresent: Boolean? = false,
    draftVersion: Int = 23,
    removeClientId: Boolean = false,
): Any {
    val paramList =
        applicableFields ?: authorisationRequestListToClientIdSchemeMap[clientIdScheme]!!
    return createAuthorizationRequest(
        paramList,
        authorizationRequestParams,
        draftVersion
    ).let { authRequestParam ->

        val param = if (isPresentationDefinitionUriPresent != true) {
            authRequestParam + clientMetadataPresentationDefinitionMap
        } else {
            if (clientIdScheme != ClientIdPrefix.PRE_REGISTERED) {
                authRequestParam + mapOf(
                    CLIENT_METADATA.value to clientMetadataMap
                )
            } else {
                authRequestParam
            }
        }.toMutableMap()

        if (removeClientId) {
            param.remove(CLIENT_ID.value)
        }

        createJWS(param, addValidSignature!!, jwtHeader)

    }
}

internal fun createAuthorizationRequest(
    paramList: List<String>,
    requestParams: Map<String, String?>,
    draftVersion: Int = 23,
    isSigned: Boolean = false,
): MutableMap<String, String?> {
    var params: List<String> = paramList
    if (draftVersion == 21) {
        params = paramList + listOf("client_id_scheme")
    }
    var authorizationRequestParam = params
        .filter { requestParams.containsKey(it) }
        .associateWith { requestParams[it] }
        .toMutableMap()
    if (isSigned) {
        val signedRequest = createJWS(authorizationRequestParam, true, null)
        authorizationRequestParam = mutableMapOf(
            "request" to signedRequest,
            CLIENT_ID.value to requestParams[CLIENT_ID.value]
        )
    }

    return authorizationRequestParam
}

fun assertOpenId4VPException(
    exception: OpenID4VPExceptions,
    expectedMessage: String,
    expectedErrorCode: String,
    expectedVerifierResponse: String? = null,
    expectedUnderlyingErrorMessage: String? = null
) {
    assertEquals(expectedMessage, exception.message)
    assertEquals(expectedErrorCode, exception.errorCode)
    if (expectedVerifierResponse != null) {
        assertEquals(expectedVerifierResponse, exception.verifierResponse.toString())
    }

    if(expectedUnderlyingErrorMessage != null) {
        assertEquals(expectedUnderlyingErrorMessage, exception.cause?.message)
    }
}

fun assertWalletConfigAndMetadata(
    walletConfig: WalletConfig,
    walletMetadata: Map<String, Any>
) {
    val vpFormatsSupported = walletMetadata["vp_formats_supported"]
    assertEquals(walletConfig.vpFormatsSupported.size, (vpFormatsSupported as Map<*, *>).size)
    assertEquals(walletConfig.vpFormatsSupported.keys.map { it.value }.toSet(), vpFormatsSupported.keys.toSet())

    walletConfig.vpFormatsSupported.forEach { (format, supportedConfig) ->
        val metadataForFormat = vpFormatsSupported[format.value] as Map<*, *>
        if (walletMetadata.containsKey("client_id_schemes_supported")) {
            assertEquals(
                supportedConfig.toAlgValuesSupported().orEmpty(),
                (metadataForFormat["alg_values_supported"] as? List<*>)?.map { it.toString() }.orEmpty()
            )
        }
    }

    val v1LdpMetadata = vpFormatsSupported[VPFormatType.LDP_VC.value] as? Map<*, *>
    val v1LdpConfig = walletConfig.vpFormatsSupported[VPFormatType.LDP_VC] as? LdpVpFormatSupported
    if (v1LdpMetadata?.containsKey("proof_type_values") == true && v1LdpConfig != null) {
        assertEquals(
            v1LdpConfig.proofTypeValues?.map { it.value }.orEmpty(),
            (v1LdpMetadata["proof_type_values"] as? List<*>)?.map { it.toString() }.orEmpty()
        )
    }

    if (walletMetadata.containsKey("client_id_prefixes_supported")) {
        assertEquals(
            walletConfig.clientIdPrefixesSupported.map { it.value },
            walletMetadata["client_id_prefixes_supported"]
        )
    }
    if (walletMetadata.containsKey("client_id_schemes_supported")) {
        assertEquals(
            walletConfig.clientIdPrefixesSupported.map { ClientIdPrefix.toClientIdScheme(it) },
            walletMetadata["client_id_schemes_supported"]
        )
    }
    assertEquals(
        walletConfig.requestObjectSigningAlgValuesSupported?.map { it.value },
        walletMetadata["request_object_signing_alg_values_supported"]
    )
    assertEquals(
        walletConfig.authorizationEncryptionAlgValuesSupported?.map { it.value },
        walletMetadata["authorization_encryption_alg_values_supported"]
    )
    assertEquals(
        walletConfig.authorizationEncryptionEncValuesSupported?.map { it.value },
        walletMetadata["authorization_encryption_enc_values_supported"]
    )
    assertEquals(walletConfig.responseTypesSupported?.map { it.value }, walletMetadata["response_types_supported"])
}
