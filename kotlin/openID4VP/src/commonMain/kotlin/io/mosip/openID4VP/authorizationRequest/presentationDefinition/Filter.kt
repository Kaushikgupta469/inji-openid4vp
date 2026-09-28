package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = Filter::class.simpleName!!

object FilterSerializer : KSerializer<Filter> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Filter") {
		element<String>("type")
		element<String>("pattern")
	}

	override fun deserialize(decoder: Decoder): Filter {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw OpenID4VPExceptions.DeserializationFailure(listOf("filter"),e.message!!, className)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject,
			className = className,
			parentField = "filter"
		)

		val type: String? =
			deserializer.deserializeField(key = "type", fieldType = "String", isMandatory = true)
		val pattern: String? =
			deserializer.deserializeField(key = "pattern", fieldType = "String", isMandatory = true)

		return Filter(
			type = type!!,
			pattern = pattern!!
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: Filter) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.type)
		builtInEncoder.encodeStringElement(descriptor, 1, value.pattern)
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = FilterSerializer::class)
class Filter(val type: String, val pattern: String) : java.io.Serializable