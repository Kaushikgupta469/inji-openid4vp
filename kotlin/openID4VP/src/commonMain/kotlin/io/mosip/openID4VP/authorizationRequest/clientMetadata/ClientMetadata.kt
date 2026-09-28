package io.mosip.openID4VP.authorizationRequest.clientMetadata

import Generated
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.*
import io.mosip.openID4VP.authorizationRequest.LdpVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.MsoMdocVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.SdJwtVpFormatSupported
import io.mosip.openID4VP.authorizationRequest.VPFormatSupported
import io.mosip.openID4VP.authorizationRequest.Validatable
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.constants.VPFormatType
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.int
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer

private val className = ClientMetadata::class.simpleName!!

object ClientMetadataSerializer : KSerializer<ClientMetadata> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("ClientMetadata") {
		element<String>("client_name", isOptional = true)
		element<String>("logo_uri", isOptional = true)
		element<String>("vp_formats_supported", isOptional = false)
		element<List<String>>("encrypted_response_enc_values_supported", isOptional = true)
		element<Jwks>("jwks", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): ClientMetadata {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw OpenID4VPExceptions.DeserializationFailure(
				listOf(CLIENT_METADATA.value), e.message!!,
				className
			)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject,
			className = className,
			parentField = CLIENT_METADATA.value
		)

		val clientName: String? =
			deserializer.deserializeField(key = "client_name", fieldType = "String")
		val logoUri: String? =
			deserializer.deserializeField(key = "logo_uri", fieldType = "String")

		val vpFormatsSupportedJson = jsonObject["vp_formats_supported"]
			?: throw OpenID4VPExceptions.InvalidInput(
				listOf(CLIENT_METADATA.value, "vp_formats_supported"), "map", className
			)

		if (vpFormatsSupportedJson !is JsonObject) {
			throw OpenID4VPExceptions.InvalidInput(
				listOf(CLIENT_METADATA.value, "vp_formats_supported"), "map", className
			)
		}

		val vpFormatsSupported = parseVpFormatsSupported(vpFormatsSupportedJson.jsonObject)

		val encryptedResponseEncValuesSupported: List<String>? =
			deserializer.deserializeField(
				key = "encrypted_response_enc_values_supported",
				fieldType = "List",
				deserializer = ListSerializer(String.serializer()),
				isMandatory = false
			)

		val jwks: Jwks? = deserializer.deserializeField(
			key = "jwks",
			fieldType = "Jwks",
			deserializer = Jwks.serializer(),
			isMandatory = false
		)

		return ClientMetadata(
			clientName = clientName,
			logoUri = logoUri,
			vpFormatsSupported = vpFormatsSupported,
			encryptedResponseEncValuesSupported = encryptedResponseEncValuesSupported,
			jwks = jwks,
		)
	}

	private fun parseVpFormatsSupported(jsonObject: JsonObject): Map<String, VPFormatSupported> {
		val result = mutableMapOf<String, VPFormatSupported>()
		for ((key, value) in jsonObject) {
			val formatType = VPFormatType.fromValue(key)
			if (value !is JsonObject) continue
			val formatObj = value.jsonObject
			val formatSupported: VPFormatSupported = when (formatType) {
				VPFormatType.LDP_VC, VPFormatType.LDP_VP -> {
					val proofTypeValues = formatObj["proof_type_values"]?.jsonArray?.map {
						io.mosip.openID4VP.constants.ProofType.fromValue(it.jsonPrimitive.content)
					}?.filterNotNull()
					val cryptoSuiteValues = formatObj["cryptosuite_values"]?.jsonArray?.map {
						it.jsonPrimitive.content
					}
					LdpVpFormatSupported(proofTypeValues = proofTypeValues, cryptoSuiteValues = cryptoSuiteValues)
				}
				VPFormatType.MSO_MDOC -> {
					val issuerAuthAlgValues = formatObj["issuerauth_alg_values"]?.jsonArray?.map { it.jsonPrimitive.int }
					val deviceAuthAlgValues = formatObj["deviceauth_alg_values"]?.jsonArray?.map { it.jsonPrimitive.int }
					MsoMdocVpFormatSupported(issuerAuthAlgValues = issuerAuthAlgValues, deviceAuthAlgValues = deviceAuthAlgValues)
				}
				VPFormatType.DC_SD_JWT, VPFormatType.VC_SD_JWT -> {
					val sdJwtAlgValues = formatObj["sd-jwt_alg_values"]?.jsonArray?.map { it.jsonPrimitive.content }
					val kbJwtAlgValues = formatObj["kb-jwt_alg_values"]?.jsonArray?.map { it.jsonPrimitive.content }
					SdJwtVpFormatSupported(sdJwtAlgValues = sdJwtAlgValues, kbJwtAlgValues = kbJwtAlgValues)
				}
				null -> continue
			}
			result[key] = formatSupported
		}
		return result
	}

	@Generated
	override fun serialize(encoder: Encoder, value: ClientMetadata) {
		require(encoder is kotlinx.serialization.json.JsonEncoder) { "ClientMetadataSerializer only supports JSON encoding" }
		val jsonObj = kotlinx.serialization.json.buildJsonObject {
			value.clientName?.let { put("client_name", kotlinx.serialization.json.JsonPrimitive(it)) }
			value.logoUri?.let { put("logo_uri", kotlinx.serialization.json.JsonPrimitive(it)) }
			put("vp_formats_supported", kotlinx.serialization.json.buildJsonObject {
				for ((key, formatSupported) in value.vpFormatsSupported) {
					put(key, kotlinx.serialization.json.buildJsonObject {
						when (formatSupported) {
							is LdpVpFormatSupported -> {
								formatSupported.proofTypeValues?.let { ptv ->
									put("proof_type_values", kotlinx.serialization.json.JsonArray(ptv.map { kotlinx.serialization.json.JsonPrimitive(it.value) }))
								}
								formatSupported.cryptoSuiteValues?.let { csv ->
									put("cryptosuite_values", kotlinx.serialization.json.JsonArray(csv.map { kotlinx.serialization.json.JsonPrimitive(it) }))
								}
							}
							is MsoMdocVpFormatSupported -> {
								formatSupported.issuerAuthAlgValues?.let { iav ->
									put("issuerauth_alg_values", kotlinx.serialization.json.JsonArray(iav.map { kotlinx.serialization.json.JsonPrimitive(it) }))
								}
								formatSupported.deviceAuthAlgValues?.let { dav ->
									put("deviceauth_alg_values", kotlinx.serialization.json.JsonArray(dav.map { kotlinx.serialization.json.JsonPrimitive(it) }))
								}
							}
							is SdJwtVpFormatSupported -> {
								formatSupported.sdJwtAlgValues?.let { sav ->
									put("sd-jwt_alg_values", kotlinx.serialization.json.JsonArray(sav.map { kotlinx.serialization.json.JsonPrimitive(it) }))
								}
								formatSupported.kbJwtAlgValues?.let { kav ->
									put("kb-jwt_alg_values", kotlinx.serialization.json.JsonArray(kav.map { kotlinx.serialization.json.JsonPrimitive(it) }))
								}
							}
						}
					})
				}
			})
			value.encryptedResponseEncValuesSupported?.let { erevs ->
				put("encrypted_response_enc_values_supported", kotlinx.serialization.json.JsonArray(erevs.map { kotlinx.serialization.json.JsonPrimitive(it) }))
			}
			value.jwks?.let {
				put("jwks", kotlinx.serialization.json.Json.encodeToJsonElement(Jwks.serializer(), it))
			}
		}
		encoder.encodeJsonElement(jsonObj)
	}
}

@Serializable(with = ClientMetadataSerializer::class)
class ClientMetadata(
	@SerialName("client_name") val clientName: String? = null,
	@SerialName("logo_uri") val logoUri: String? = null,
	@SerialName("vp_formats_supported") val vpFormatsSupported: Map<String, VPFormatSupported>,
	@SerialName("encrypted_response_enc_values_supported") val encryptedResponseEncValuesSupported: List<String>? = null,
	@SerialName("jwks") val jwks: Jwks? = null,
) : Validatable, java.io.Serializable {
	override fun validate() {
		if (vpFormatsSupported.isEmpty()) {
			throw OpenID4VPExceptions.InvalidInput(
				listOf(CLIENT_METADATA.value, "vp_formats_supported"), "map",
				className
			)
		}
		return
	}
}
