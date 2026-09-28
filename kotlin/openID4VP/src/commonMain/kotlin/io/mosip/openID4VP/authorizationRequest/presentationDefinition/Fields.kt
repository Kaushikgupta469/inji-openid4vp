package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = Fields::class.simpleName!!

object FieldsSerializer : KSerializer<Fields> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Fields") {
		element<List<String>>("path")
		element<String>("id", isOptional = true)
		element<String>("purpose", isOptional = true)
		element<String>("name", isOptional = true)
		element<Filter>("filter", isOptional = true)
		element<Boolean>("optional", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): Fields {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw OpenID4VPExceptions.DeserializationFailure(listOf("fields"),e.message!!, className)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject,
			className = className,
			parentField = "fields"
		)

		val path: List<String>? =
			deserializer.deserializeField(
				key = "path",
				fieldType = "List<String>",
				isMandatory = true
			)
		val id: String? = deserializer.deserializeField(key = "id", fieldType = "String")
		val purpose: String? = deserializer.deserializeField(key = "purpose", fieldType = "String")
		val name: String? = deserializer.deserializeField(key = "name", fieldType = "String")
		val filter: Filter? = deserializer.deserializeField(
			key = "filter",
			fieldType = "Filter",
			deserializer = Filter.serializer()
		)
		val optional: Boolean? =
			deserializer.deserializeField(key = "optional", fieldType = "Boolean")

		return Fields(
			path = path!!,
			id = id,
			purpose = purpose,
			name = name,
			filter = filter,
			optional = optional
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: Fields) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeSerializableElement(
			descriptor,
			0,
			ListSerializer(String.serializer()),
			value.path
		)
		value.id?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		value.purpose?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
		value.name?.let { builtInEncoder.encodeStringElement(descriptor, 3, it) }
		value.filter?.let {
			builtInEncoder.encodeSerializableElement(
				descriptor,
				4,
				Filter.serializer(),
				it
			)
		}
		value.optional?.let { builtInEncoder.encodeBooleanElement(descriptor, 5, it) }
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = FieldsSerializer::class)
class Fields(
	val path: List<String>,
	val id: String? = null,
	val purpose: String? = null,
	val name: String? = null,
	val filter: Filter? = null,
	val optional: Boolean? = null
) : java.io.Serializable {
	fun validate() {
		try {
			val pathPrefixes = listOf("$.", "$[")
			path.forEach { p ->
				val isNotValidPrefix = !(pathPrefixes.any { p.startsWith(it) })
				if (isNotValidPrefix) {
					throw OpenID4VPExceptions.InvalidInputPattern(listOf("fields","path"), className)
				}
			}
		} catch (exception: Exception) {
			throw exception
		}
	}

}