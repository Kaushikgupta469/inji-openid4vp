package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.builtins.MapSerializer
import kotlinx.serialization.builtins.serializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = InputDescriptor::class.simpleName!!
object InputDescriptorSerializer : KSerializer<InputDescriptor> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("InputDescriptor") {
		element<String>("id")
		element<String>("name", isOptional = true)
		element<String>("purpose", isOptional = true)
		element<Map<String, Map<String,List<String>>>>("format", isOptional = true)
		element<Constraints>("constraints")
	}

	override fun deserialize(decoder: Decoder): InputDescriptor {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw  OpenID4VPExceptions.DeserializationFailure(listOf("input_descriptor"),e.message!!,
				className)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject,
			className = className,
			parentField = "input_descriptor"
		)

		val id: String? =
			deserializer.deserializeField(key = "id", fieldType = "String", isMandatory = true)
		val name: String? =
			deserializer.deserializeField(key = "name", fieldType = "String")
		val purpose: String? =
			deserializer.deserializeField(key = "purpose", fieldType = "String")
		val format: Map<String, Map<String,List<String>>>? =
			deserializer.deserializeField(
				key = "format",
				fieldType = "Map"
			)
		val constraints: Constraints? =
			deserializer.deserializeField(
				key = "constraints",
				fieldType = "Constraints",
				deserializer = Constraints.serializer(),
				isMandatory = true
			)

		return InputDescriptor(
			id = id!!,
			name = name,
			purpose = purpose,
			format = format,
			constraints = constraints!!
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: InputDescriptor) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.id)
		value.name?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		value.purpose?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
		value.format?.let {
			builtInEncoder.encodeSerializableElement(
				descriptor, 3, MapSerializer(
					String.serializer(),
					MapSerializer(
						String.serializer(),
						ListSerializer(String.serializer())
					)
				), it
			)
		}
		builtInEncoder.encodeSerializableElement(
			descriptor, 4, Constraints.serializer(), value.constraints
		)
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = InputDescriptorSerializer::class)
class InputDescriptor(
	val id: String,
	val name: String? = null,
	val purpose: String? = null,
	val format: Map<String, Map<String,List<String>>>? = null,
	val constraints: Constraints
) : java.io.Serializable {
	fun validate() {
		try {
			constraints.validate()
		} catch (exception: OpenID4VPExceptions.InvalidInput) {
			throw exception
		}
	}
}
