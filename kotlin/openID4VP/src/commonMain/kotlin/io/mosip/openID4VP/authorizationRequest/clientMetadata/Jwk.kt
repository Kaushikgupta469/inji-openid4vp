package io.mosip.openID4VP.authorizationRequest.clientMetadata

import Generated
import io.mosip.openID4VP.common.FieldDeserializer
import io.mosip.openID4VP.constants.SignatureAlgorithm
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


private val className = Jwk::class.simpleName!!

object JwkSerializer : KSerializer<Jwk> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("Jwk") {
        element<String>("kty", isOptional = false)
        element<String>("use", isOptional = true)
        element<String>("crv", isOptional = false)
        element<String>("x", isOptional = false)
        element<String>("alg", isOptional = false)
        element<String>("kid", isOptional = false)
        element<String>("y", isOptional = true)
    }

    override fun deserialize(decoder: Decoder): Jwk {
        val jsonDecoder = try {
            decoder as JsonDecoder
        } catch (e: ClassCastException) {
            throw OpenID4VPExceptions.DeserializationFailure(listOf("jwk"), e.message!!, className)
        }

        val jsonObject = jsonDecoder.decodeJsonElement().jsonObject
        val deserializer = FieldDeserializer(
            jsonObject = jsonObject, className = className, parentField = "jwk"
        )

        val kty: String = deserializer.deserializeField(
            key = "kty",
            fieldType = "String",
            isMandatory = true
        )!!
        val use: String? = deserializer.deserializeField(
            key = "use",
            fieldType = "String",
        )
        val crv: String = deserializer.deserializeField(
            key = "crv",
            fieldType = "String",
            isMandatory = true
        )!!
        val x: String = deserializer.deserializeField(
            key = "x",
            fieldType = "String",
            isMandatory = true
        )!!
        val alg: String = deserializer.deserializeField(
            key = "alg",
            fieldType = "String",
            isMandatory = true
        )!!
        val kid: String = deserializer.deserializeField(
            key = "kid",
            fieldType = "String",
            isMandatory = true
        )!!
        val y: String? = deserializer.deserializeField(
            key = "y",
            fieldType = "String",
        )
        return Jwk(kty = kty, use = use, crv = crv, x = x, alg = alg, kid = kid, y = y)
    }


    @Generated
    override fun serialize(encoder: Encoder, value: Jwk) {
        val builtInEncoder = encoder.beginStructure(descriptor)
        builtInEncoder.encodeStringElement(descriptor, 0, value.kty)
        value.use?.let { builtInEncoder.encodeStringElement(descriptor, 1, it) }
        value.crv?.let { builtInEncoder.encodeStringElement(descriptor, 2, it) }
        builtInEncoder.encodeStringElement(descriptor, 3, value.x)
        value.alg?.let { builtInEncoder.encodeStringElement(descriptor, 4, it) }
        value.kid?.let { builtInEncoder.encodeStringElement(descriptor, 5, it) }
        value.y?.let { builtInEncoder.encodeStringElement(descriptor, 6, it) }
        builtInEncoder.endStructure(descriptor)
    }
}

@Serializable(with = JwkSerializer::class)
data class Jwk(
    val kty: String,
    val use: String? = null,
    val crv: String? = null,
    val x: String,
    val alg: String? = null,
    val kid: String? = null,
    val y: String? = null,

    ) : java.io.Serializable {

    fun supports(algorithm: SignatureAlgorithm): Boolean {
        return when (algorithm) {
            SignatureAlgorithm.EdDSA ->
                kty.equals("OKP", ignoreCase = true) &&
                        crv.equals("Ed25519", ignoreCase = true)
        }
    }
}
