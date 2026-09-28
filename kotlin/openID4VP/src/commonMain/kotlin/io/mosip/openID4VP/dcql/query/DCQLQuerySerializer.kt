package io.mosip.openID4VP.dcql.query

import Generated
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.KSerializer
import kotlinx.serialization.builtins.ListSerializer
import kotlinx.serialization.descriptors.SerialDescriptor
import kotlinx.serialization.descriptors.buildClassSerialDescriptor
import kotlinx.serialization.encoding.Decoder
import kotlinx.serialization.encoding.Encoder
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonDecoder
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonEncoder
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.doubleOrNull
import kotlinx.serialization.json.floatOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.longOrNull

internal object DCQLQuerySerializer : KSerializer<DCQLQuery> {
    override val descriptor: SerialDescriptor = buildClassSerialDescriptor("DCQLQuery") {
        element("credentials", ListSerializer(JsonObject.serializer()).descriptor)
        element(
            "credential_sets",
            ListSerializer(JsonObject.serializer()).descriptor,
            isOptional = true
        )
    }

    override fun deserialize(decoder: Decoder): DCQLQuery {
        val jsonDecoder = try {
            decoder as JsonDecoder
        } catch (e: ClassCastException) {
            throw OpenID4VPExceptions.DeserializationFailure(
                listOf("dcql_query"),
                e.message!!,
                DCQL_QUERY_CLASS_NAME
            )
        }

        val jsonObject = try {
            jsonDecoder.decodeJsonElement().jsonObject
        } catch (e: IllegalArgumentException) {
            throw OpenID4VPExceptions.DeserializationFailure(
                listOf("dcql_query"),
                e.message ?: "dcql_query must be a JSON object",
                DCQL_QUERY_CLASS_NAME
            )
        }

        return parseDcqlQuery(jsonObject)
    }

    @Generated
    override fun serialize(encoder: Encoder, value: DCQLQuery) {
        val jsonEncoder = try {
            encoder as JsonEncoder
        } catch (e: ClassCastException) {
            throw OpenID4VPExceptions.JsonEncodingFailed(
                "dcql_query",
                e.message ?: "DCQLQuerySerializer only supports JSON encoding",
                DCQL_QUERY_CLASS_NAME
            )
        }

        jsonEncoder.encodeJsonElement(value.toJsonObject())
    }
}

private fun parseDcqlQuery(jsonObject: JsonObject): DCQLQuery {
    val credentials = jsonObject.requiredArray("credentials", listOf("dcql_query", "credentials"))
        .mapIndexed { index, credentialElement ->
            parseCredentialQuery(
                credentialElement.requireJsonObject(
                    listOf("dcql_query", "credentials", index.toString()),
                    DCQL_QUERY_CLASS_NAME
                )
            )
        }

    val credentialSets =
        jsonObject.optionalArray("credential_sets", listOf("dcql_query", "credential_sets"))
            ?.mapIndexed { index, credentialSetElement ->
                parseCredentialSetQuery(
                    credentialSetElement.requireJsonObject(
                        listOf("dcql_query", "credential_sets", index.toString()),
                        DCQL_QUERY_CLASS_NAME
                    )
                )
            }

    return DCQLQuery(credentials = credentials, credentialSets = credentialSets)
}

private fun parseCredentialQuery(jsonObject: JsonObject): CredentialQuery {
    val id = jsonObject.requiredString(
        "id",
        listOf("credential_query", "id"),
        CREDENTIAL_QUERY_CLASS_NAME
    )
    val format = jsonObject.requiredString(
        "format",
        listOf("credential_query", "format"),
        CREDENTIAL_QUERY_CLASS_NAME
    )
    val multiple = jsonObject.optionalBoolean(
        "multiple",
        listOf("credential_query", "multiple"),
        CREDENTIAL_QUERY_CLASS_NAME
    ) ?: false
    val meta = jsonObject.optionalObject(
        "meta",
        listOf("credential_query", "meta"),
        CREDENTIAL_QUERY_CLASS_NAME
    )
        ?.toDynamicMap() ?: emptyMap()
    val requireCryptographicHolderBinding = jsonObject.optionalBoolean(
        "require_cryptographic_holder_binding",
        listOf("credential_query", "require_cryptographic_holder_binding"),
        CREDENTIAL_QUERY_CLASS_NAME
    ) ?: true
    val claims = jsonObject.optionalArray("claims", listOf("credential_query", "claims"))
        ?.mapIndexed { index, claimElement ->
            parseClaimsQuery(
                claimElement.requireJsonObject(
                    listOf("credential_query", "claims", index.toString()),
                    CREDENTIAL_QUERY_CLASS_NAME
                )
            )
        }
    val claimSets = jsonObject.optionalArray("claim_sets", listOf("credential_query", "claim_sets"))
        ?.mapIndexed { index, claimSetElement ->
            claimSetElement.requireJsonArray(
                listOf("credential_query", "claim_sets", index.toString()),
                CREDENTIAL_QUERY_CLASS_NAME
            ).mapIndexed { nestedIndex, claimIdElement ->
                claimIdElement.requireJsonPrimitive(
                    listOf(
                        "credential_query",
                        "claim_sets",
                        index.toString(),
                        nestedIndex.toString()
                    ),
                    CREDENTIAL_QUERY_CLASS_NAME,
                    expected = "String"
                ).content
            }
        }

    return CredentialQuery(
        id = id,
        format = format,
        multiple = multiple,
        meta = meta,
        requireCryptographicHolderBinding = requireCryptographicHolderBinding,
        claims = claims,
        claimSets = claimSets
    )
}

private fun parseClaimsQuery(jsonObject: JsonObject): ClaimsQuery {
    val id = jsonObject.optionalString("id", listOf("claims_query", "id"), CLAIMS_QUERY_CLASS_NAME)
    val path = jsonObject.requiredArray("path", listOf("claims_query", "path"))
        .map { pathEntry -> pathEntry.toDynamicValue() }
    val values = jsonObject.optionalArray("values", listOf("claims_query", "values"))
        ?.map { valueElement -> ClaimValue.from(valueElement.toDynamicValue()) }

    return ClaimsQuery(id = id, path = path, values = values)
}

private fun parseCredentialSetQuery(jsonObject: JsonObject): CredentialSetQuery {
    val options = jsonObject.requiredArray("options", listOf("credential_set_query", "options"))
        .mapIndexed { index, optionElement ->
            optionElement.requireJsonArray(
                listOf("credential_set_query", "options", index.toString()),
                CREDENTIAL_SET_QUERY_CLASS_NAME
            ).mapIndexed { nestedIndex, credentialIdElement ->
                credentialIdElement.requireJsonPrimitive(
                    listOf(
                        "credential_set_query",
                        "options",
                        index.toString(),
                        nestedIndex.toString()
                    ),
                    CREDENTIAL_SET_QUERY_CLASS_NAME,
                    expected = "String"
                ).content
            }
        }
    val required = jsonObject.optionalBoolean(
        "required",
        listOf("credential_set_query", "required"),
        CREDENTIAL_SET_QUERY_CLASS_NAME
    ) ?: true

    return CredentialSetQuery(options = options, required = required)
}

private fun DCQLQuery.toJsonObject(): JsonObject = buildJsonObject {
    put("credentials", buildJsonArray {
        credentials.forEach { credential ->
            add(credential.toJsonObject())
        }
    })
    credentialSets?.let { sets ->
        put("credential_sets", buildJsonArray {
            sets.forEach { credentialSet ->
                add(credentialSet.toJsonObject())
            }
        })
    }
}

private fun CredentialQuery.toJsonObject(): JsonObject = buildJsonObject {
    put("id", JsonPrimitive(id))
    put("format", JsonPrimitive(format))
    put("meta", meta.toJsonObject())
    if (multiple) {
        put("multiple", JsonPrimitive(multiple))
    }
    if (!requireCryptographicHolderBinding) {
        put(
            "require_cryptographic_holder_binding",
            JsonPrimitive(requireCryptographicHolderBinding)
        )
    }
    claims?.let { claimQueries ->
        put("claims", buildJsonArray {
            claimQueries.forEach { claimQuery ->
                add(claimQuery.toJsonObject())
            }
        })
    }
    claimSets?.let { sets ->
        put("claim_sets", buildJsonArray {
            sets.forEach { claimSet ->
                add(buildJsonArray {
                    claimSet.forEach { claimId ->
                        add(JsonPrimitive(claimId))
                    }
                })
            }
        })
    }
}

private fun CredentialSetQuery.toJsonObject(): JsonObject = buildJsonObject {
    put("options", buildJsonArray {
        options.forEach { option ->
            add(buildJsonArray {
                option.forEach { credentialId ->
                    add(JsonPrimitive(credentialId))
                }
            })
        }
    })
    if (!required) {
        put("required", JsonPrimitive(required))
    }
}

private fun ClaimsQuery.toJsonObject(): JsonObject = buildJsonObject {
    id?.let { put("id", JsonPrimitive(it)) }
    put("path", JsonArray(path.map { it.toJsonElement(listOf("claims_query", "path")) }))
    values?.let { claimValues ->
        put("values", JsonArray(claimValues.map { it.toJsonElement() }))
    }
}

private fun ClaimValue.toJsonElement(): JsonElement = when (this) {
    is ClaimValue.StringValue -> JsonPrimitive(value)
    is ClaimValue.LongValue -> JsonPrimitive(value)
    is ClaimValue.BoolValue -> JsonPrimitive(value)
}

private fun Map<String, Any>.toJsonObject(): JsonObject = buildJsonObject {
    for ((key, value) in this@toJsonObject) {
        put(key, value.toJsonElement(listOf("credential_query", "meta", key)))
    }
}

private fun Any?.toJsonElement(fieldPath: List<String>): JsonElement = when (this) {
    null -> JsonNull
    is JsonElement -> this
    is String -> JsonPrimitive(this)
    is Boolean -> JsonPrimitive(this)
    is Number -> JsonPrimitive(this)
    is Map<*, *> -> buildJsonObject {
        for ((key, value) in this@toJsonElement) {
            val stringKey = key as? String ?: throw OpenID4VPExceptions.JsonEncodingFailed(
                fieldPath,
                "Only string keys are supported while serializing dynamic JSON objects",
                DCQL_QUERY_CLASS_NAME
            )
            put(stringKey, value.toJsonElement(fieldPath + stringKey))
        }
    }

    is List<*> -> JsonArray(mapIndexed { index, value -> value.toJsonElement(fieldPath + index.toString()) })
    else -> throw OpenID4VPExceptions.JsonEncodingFailed(
        fieldPath,
        "Unsupported value type '${this::class.simpleName}' while serializing dcql_query",
        DCQL_QUERY_CLASS_NAME
    )
}

private fun JsonObject.requiredString(
    key: String,
    fieldPath: List<String>,
    className: String
): String {
    val element = this[key] ?: throw OpenID4VPExceptions.MissingInput(fieldPath, "", className)
    return element.requireJsonPrimitive(fieldPath, className, expected = "String").content
}

private fun JsonObject.optionalString(
    key: String,
    fieldPath: List<String>,
    className: String
): String? {
    val element = this[key] ?: return null
    return element.requireJsonPrimitive(fieldPath, className, expected = "String").content
}

private fun JsonObject.optionalBoolean(
    key: String,
    fieldPath: List<String>,
    className: String
): Boolean? {
    val element = this[key] ?: return null
    return element.requireJsonPrimitive(fieldPath, className, expected = "Boolean").booleanOrNull
        ?: throw OpenID4VPExceptions.InvalidInput(fieldPath, "Boolean", className)
}

private fun JsonObject.requiredArray(key: String, fieldPath: List<String>): JsonArray {
    val element =
        this[key] ?: throw OpenID4VPExceptions.MissingInput(fieldPath, "", DCQL_QUERY_CLASS_NAME)
    return element.requireJsonArray(fieldPath, DCQL_QUERY_CLASS_NAME)
}

private fun JsonObject.optionalArray(key: String, fieldPath: List<String>): JsonArray? {
    val element = this[key] ?: return null
    return element.requireJsonArray(fieldPath, DCQL_QUERY_CLASS_NAME)
}

private fun JsonObject.optionalObject(
    key: String,
    fieldPath: List<String>,
    className: String
): JsonObject? {
    val element = this[key] ?: return null
    return element.requireJsonObject(fieldPath, className)
}

private fun JsonElement.requireJsonObject(fieldPath: List<String>, className: String): JsonObject {
    return this as? JsonObject ?: throw OpenID4VPExceptions.InvalidInput(
        fieldPath,
        "map",
        className
    )
}

private fun JsonElement.requireJsonArray(fieldPath: List<String>, className: String): JsonArray {
    return this as? JsonArray ?: throw OpenID4VPExceptions.InvalidInput(fieldPath, null, className)
}

private fun JsonElement.requireJsonPrimitive(
    fieldPath: List<String>,
    className: String,
    expected: String
): JsonPrimitive {
    val primitive = this as? JsonPrimitive ?: throw OpenID4VPExceptions.InvalidInput(
        fieldPath,
        expected,
        className
    )
    if (primitive == JsonNull) {
        throw OpenID4VPExceptions.InvalidInput(fieldPath, expected, className)
    }
    if (expected == "String" && !primitive.isString) {
        throw OpenID4VPExceptions.InvalidInput(fieldPath, expected, className)
    }
    return primitive
}

private fun JsonObject.toDynamicMap(): Map<String, Any> = buildMap {
    this@toDynamicMap.entries.forEach { (key, value) ->
        val v = value.toDynamicValue()
        if (v != null) put(key, v)
    }
}

private fun JsonElement.toDynamicValue(): Any? = when (this) {
    JsonNull -> null
    is JsonPrimitive -> when {
        isString -> content
        booleanOrNull != null -> booleanOrNull
        intOrNull != null -> intOrNull
        longOrNull != null -> longOrNull
        floatOrNull != null -> floatOrNull
        doubleOrNull != null -> doubleOrNull
        else -> content
    }

    is JsonArray -> map { it.toDynamicValue() }
    is JsonObject -> entries.associate { (key, value) -> key to value.toDynamicValue() }
}
