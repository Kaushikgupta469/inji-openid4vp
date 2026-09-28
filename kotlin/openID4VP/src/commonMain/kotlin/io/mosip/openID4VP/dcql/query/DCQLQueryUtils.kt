package io.mosip.openID4VP.dcql.query

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions

private const val CLASS_NAME = "DcqlQueryParser"

@Suppress("UNCHECKED_CAST")
internal fun parseAndValidateDcqlQuery(
    authorizationRequest: MutableMap<String, Any>
): MutableMap<String, Any> {
    val dcqlQueryKey = AuthorizationRequestFieldConstants.DCQL_QUERY.value
    val dcqlQuery = authorizationRequest[dcqlQueryKey]
        ?: throw OpenID4VPExceptions.MissingInput(
            listOf("authorizationRequest", dcqlQueryKey), "", CLASS_NAME
        )

    if (authorizationRequest.containsKey(AuthorizationRequestFieldConstants.SCOPE.value)) {
        throw OpenID4VPExceptions.InvalidData(
            "The request contains both a dcql_query parameter and a scope parameter",
            CLASS_NAME
        )
    }

    val parsedDcqlQuery: DCQLQuery = when (dcqlQuery) {
        is String -> parseDcqlQueryFromString(dcqlQuery)
        is Map<*, *> -> parseDcqlQueryFromMap(dcqlQuery as Map<String, Any>)
        else -> throw OpenID4VPExceptions.InvalidData(
            "The dcql_query parameter must be a string or a JSON object",
            CLASS_NAME
        )
    }

    authorizationRequest[dcqlQueryKey] = parsedDcqlQuery
    return authorizationRequest
}

private fun parseDcqlQueryFromString(jsonString: String): DCQLQuery {
    return try {
        val objectMapper = getObjectMapper()
        val map = objectMapper.readValue(jsonString, Map::class.java) as Map<String, Any>
        parseDcqlQueryFromMap(map)
    } catch (e: OpenID4VPExceptions) {
        throw e
    } catch (e: Exception) {
        throw OpenID4VPExceptions.InvalidData(
            "Failed to parse dcql_query: ${e.message}",
            CLASS_NAME
        )
    }
}

@Suppress("UNCHECKED_CAST")
private fun parseDcqlQueryFromMap(map: Map<String, Any>): DCQLQuery {
    val credentialsRaw = map["credentials"] as? List<Map<String, Any>>
        ?: throw OpenID4VPExceptions.MissingInput(
            listOf("dcql_query", "credentials"), "", CLASS_NAME
        )

    val credentials = credentialsRaw.map { parseCredentialQuery(it) }

    val credentialSetsRaw = map["credential_sets"] as? List<Map<String, Any>>
    val credentialSets = credentialSetsRaw?.map { parseCredentialSetQuery(it) }

    return DCQLQuery(credentials = credentials, credentialSets = credentialSets)
}

@Suppress("UNCHECKED_CAST")
private fun parseCredentialQuery(map: Map<String, Any>): CredentialQuery {
    val id = map["id"] as? String
        ?: throw OpenID4VPExceptions.MissingInput(
            listOf("credential_query", "id"), "", CLASS_NAME
        )
    val format = map["format"] as? String
        ?: throw OpenID4VPExceptions.MissingInput(
            listOf("credential_query", "format"), "", CLASS_NAME
        )
    val multiple = map["multiple"] as? Boolean ?: false
    val meta = (map["meta"] as? Map<*, *>)
        ?.let { normalizeMap(it, listOf("credential_query", "meta")) }
        ?: emptyMap()
    val requireCryptographicHolderBinding =
        map["require_cryptographic_holder_binding"] as? Boolean ?: true

    val claimsRaw = map["claims"] as? List<Map<String, Any>>
    val claims = claimsRaw?.map { parseClaimsQuery(it) }

    val claimSets = map["claim_sets"] as? List<List<String>>

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

@Suppress("UNCHECKED_CAST")
private fun parseClaimsQuery(map: Map<String, Any>): ClaimsQuery {
    val id = map["id"] as? String
    val pathRaw = map["path"] as? List<*>
        ?: throw OpenID4VPExceptions.MissingInput(
            listOf("claims_query", "path"), "", CLASS_NAME
        )
    val path = pathRaw.map { normalizeValue(it, listOf("claims_query", "path")) }

    val valuesRaw = map["values"] as? List<Any>
    val values = valuesRaw?.map { ClaimValue.from(it) }

    return ClaimsQuery(id = id, path = path, values = values)
}

private fun normalizeMap(map: Map<*, *>, fieldPath: List<String>): Map<String, Any> = buildMap {
    map.forEach { (key, value) ->
        val stringKey = key as? String ?: throw OpenID4VPExceptions.InvalidData(
            "meta keys must be strings at ${fieldPath.joinToString(".")}", CLASS_NAME
        )
        val normalized = normalizeValue(value, fieldPath + stringKey)
        if (normalized != null) put(stringKey, normalized)
    }
}

private fun normalizeValue(value: Any?, fieldPath: List<String>): Any? = when (value) {
    null -> null
    is String, is Boolean, is Number -> value
    is List<*> -> value.map { normalizeValue(it, fieldPath) }
    is Map<*, *> -> normalizeMap(value, fieldPath)
    else -> throw OpenID4VPExceptions.InvalidData(
        "Non-serializable value of type '${value::class.simpleName}' at ${fieldPath.joinToString(".")}",
        CLASS_NAME
    )
}

@Suppress("UNCHECKED_CAST")
private fun parseCredentialSetQuery(map: Map<String, Any>): CredentialSetQuery {
    val options = map["options"] as? List<List<String>>
        ?: throw OpenID4VPExceptions.MissingInput(
            listOf("credential_set_query", "options"), "", CLASS_NAME
        )
    val required = map["required"] as? Boolean ?: true

    return CredentialSetQuery(options = options, required = required)
}
