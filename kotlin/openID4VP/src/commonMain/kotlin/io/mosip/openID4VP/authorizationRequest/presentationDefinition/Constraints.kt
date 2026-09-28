package io.mosip.openID4VP.authorizationRequest.presentationDefinition

import Generated
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.SerialName
import kotlinx.serialization.Serializable
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.descriptors.element
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.jsonObject

private val className = Constraints::class.simpleName!!
object ConstraintsSerializer : KSerializer<Constraints> {
	override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Constraints") {
		element<List<Fields>>("fields", isOptional = true)
		element<String>("limit_disclosure", isOptional = true)
	}

	override fun deserialize(decoder: Decoder): Constraints {
		val jsonDecoder = try {
			decoder as JsonDecoder
		} catch (e: ClassCastException) {
			throw OpenID4VPExceptions.DeserializationFailure( listOf("constraints"),e.message!!,
				className)
		}

		val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
		val deserializer = FieldDeserializer(
			jsonObject = jsonObject, className = className, parentField = "constraints"
		)

		val fields: List<Fields>? = deserializer.deserializeField(
			key = "fields",
			fieldType = "List<Fields>",
			deserializer = ListSerializer(Fields.serializer()),
		)
		val limitDisclosure: String? = deserializer.deserializeField(
			key = "limit_disclosure",
			fieldType = "String",
		)

		return Constraints(
			fields = fields, limitDisclosure = limitDisclosure
		)
	}

	@Generated
	override fun serialize(encoder: Encoder, value: Constraints) {
		val builtInEncoder = encoder.beginStructure(descriptor)
		value.fields?.let {
			builtInEncoder.encodeSerializableElement(
				descriptor,
				0,
				ListSerializer(Fields.serializer()),
				it
			)
		}
		value.limitDisclosure?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
		builtInEncoder.endStructure(descriptor)
	}
}

@Serializable(with = ConstraintsSerializer::class)
class Constraints(
	val fields: List<Fields>? = null,
	@SerialName("limit_disclosure") val limitDisclosure: String? = null
) : java.io.Serializable {
	fun validate() {
		try {
			fields?.forEach { field ->
				field.validate()
			}

			limitDisclosure?.let {
				LimitDisclosure.entries.firstOrNull { it.value == limitDisclosure }
					?: throw OpenID4VPExceptions.InvalidLimitDisclosure(className)
			}
		} catch (exception: Exception) {
			throw exception
		}
	}
}

