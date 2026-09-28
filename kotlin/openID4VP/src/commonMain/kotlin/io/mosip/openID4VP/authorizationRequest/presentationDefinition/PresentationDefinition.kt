package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.PRESENTATION_DEFINITION
import io.mosip.openID4VP.authorizationRequest.Validatable
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
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

private val className = PresentationDefinition::class.simpleName!!

object PresentationDefinitionSerializer : KSerializer<PresentationDefinition> {
	override val descriptor: SerialDescriptor =
		buildClassSerialDescriptor("PresentationDefinition") {
			element<String>("id")
			element<ArrayList<InputDescriptor>>("input_descriptors")
			element<String>("name", isOptional = true)
			element<String>("purpose", isOptional = true)
			element<Map<String, Map<String,List<String>>>>("format", isOptional = true)
		}

	override fun deserialize(decoder: Decoder): PresentationDefinition {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw OpenID4VPExceptions.DeserializationFailure(listOf(PRESENTATION_DEFINITION.value),e.message!!,
				className)
		}
		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject, className = className, parentField = PRESENTATION_DEFINITION.value
		)

		val id: String? =
			deserializer.deserializeField(key = "id", fieldType = "String", isMandatory = true)
		val inputDescriptors: List<InputDescriptor>? = deserializer.deserializeField(
			key = "input_descriptors",
			fieldType = "List<InputDescriptor>",
			deserializer = ListSerializer(InputDescriptor.serializer()),
			isMandatory = true
		)
		val name: String? = deserializer.deserializeField(key = "name", fieldType = "String")
		val purpose: String? = deserializer.deserializeField(key = "purpose", fieldType = "String")
		val format: Map<String, Map<String, List<String>>>? = deserializer.deserializeField(
			key = "format", fieldType = "Map"
		)
		return PresentationDefinition(
			id = id!!, inputDescriptors = inputDescriptors!!,
			name = name, purpose = purpose, format = format
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: PresentationDefinition) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		builtInEncoder.encodeStringElement(descriptor, 0, value.id)
		builtInEncoder.encodeSerializableElement(
			descriptor,
			1,
			ListSerializer(InputDescriptor.serializer()),
			value.inputDescriptors
		)
		value.name?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
		value.purpose?.let { builtInEncoder.encodeStringElement(descriptor, 3, it) }
		value.format?.let {
			builtInEncoder.encodeSerializableElement(
				descriptor,
				4,
				MapSerializer(
					String.serializer(),
					MapSerializer(
						String.serializer(),
						ListSerializer(String.serializer())
					)
				),
				it
			)
		}
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = PresentationDefinitionSerializer::class)
class PresentationDefinition(
	val id: String,
	@SerialName("input_descriptors")
    val inputDescriptors: List<InputDescriptor>,
	val name: String? = null,
	val purpose: String? = null,
	val format: Map<String, Map<String,List<String>>>? = null
) : Validatable, java.io.Serializable {

	override fun validate() {
		try {
			inputDescriptors.forEach { inputDescriptor ->
				inputDescriptor.validate()
			}
		} catch (exception: OpenID4VPExceptions.InvalidInput) {
			throw exception
		}
	}
}

