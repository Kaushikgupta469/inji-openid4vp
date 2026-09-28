package io.mosip.openID4VP.dcql.query

import io.mosip.openID4VP.authorizationRequest.Validatable
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import kotlinx.serialization.Serializable

val VALID_ID_PATTERN = Regex("^[a-zA-Z0-9_-]+$")
const val DCQL_QUERY_CLASS_NAME = "DCQLQuery"
const val CREDENTIAL_QUERY_CLASS_NAME = "CredentialQuery"
const val CREDENTIAL_SET_QUERY_CLASS_NAME = "CredentialSetQuery"
const val CLAIM_VALUE_CLASS_NAME = "ClaimValue"
const val CLAIMS_QUERY_CLASS_NAME = "ClaimsQuery"

@Serializable(with = DCQLQuerySerializer::class)
data class DCQLQuery(
    val credentials: List<CredentialQuery>,
    val credentialSets: List<CredentialSetQuery>? = null
) : Validatable, java.io.Serializable {

    init {
        validate()
    }

    override fun validate() {
        if (credentials.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("dcql_query", "credentials"), null, DCQL_QUERY_CLASS_NAME
            )
        }

        val credentialQueryIds = credentials.map { it.id }
        if (credentialQueryIds.size != credentialQueryIds.toSet().size) {
            throw OpenID4VPExceptions.InvalidData(
                "Credential Query ids must be unique within dcql_query",
                DCQL_QUERY_CLASS_NAME
            )
        }

        for (credentialQuery in credentials) {
            credentialQuery.validate()
        }

        credentialSets?.let { sets ->
            if (sets.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("dcql_query", "credential_sets"), null, DCQL_QUERY_CLASS_NAME
                )
            }
            for (credentialSet in sets) {
                credentialSet.validateCredentialIdReferences(credentialQueryIds.toSet())
            }
        }
    }
}

data class CredentialQuery(
    val id: String,
    val format: String,
    val multiple: Boolean = false,
    val meta: Map<String, Any> = emptyMap(),
    val requireCryptographicHolderBinding: Boolean = true,
    val claims: List<ClaimsQuery>? = null,
    val claimSets: List<List<String>>? = null
) : java.io.Serializable {
    internal fun validate() {
        if (!VALID_ID_PATTERN.matches(id)) {
            throw OpenID4VPExceptions.InvalidData(
                "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
                CREDENTIAL_QUERY_CLASS_NAME
            )
        }

        if (format.isBlank()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("credential_query", "format"), null, CREDENTIAL_QUERY_CLASS_NAME
            )
        }

        claims?.let { claimsList ->
            if (claimsList.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_query", "claims"), null, CREDENTIAL_QUERY_CLASS_NAME
                )
            }

            val claimIds = claimsList.mapNotNull { it.id }
            if (claimIds.size != claimIds.toSet().size) {
                throw OpenID4VPExceptions.InvalidData(
                    "Claim ids must be unique within a Credential Query",
                    CREDENTIAL_QUERY_CLASS_NAME
                )
            }

            for (claim in claimsList) {
                claim.validate(isClaimSetsAvailable = claimSets != null)
            }
        }

        claimSets?.let { sets ->
            if (claims == null) {
                throw OpenID4VPExceptions.InvalidData(
                    "claim_sets must not be present when claims is absent",
                    CREDENTIAL_QUERY_CLASS_NAME
                )
            }
            if (sets.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_query", "claim_sets"), null, CREDENTIAL_QUERY_CLASS_NAME
                )
            }
            val validClaimIds = claims.mapNotNull { it.id }.toSet()
            for (claimSet in sets) {
                if (claimSet.isEmpty()) {
                    throw OpenID4VPExceptions.InvalidInput(
                        listOf("credential_query", "claim_sets"), null, CREDENTIAL_QUERY_CLASS_NAME
                    )
                }
                for (claimId in claimSet) {
                    if (!validClaimIds.contains(claimId)) {
                        throw OpenID4VPExceptions.InvalidData(
                            "claim_sets references unknown claim id '$claimId'",
                            CREDENTIAL_QUERY_CLASS_NAME
                        )
                    }
                }
            }
        }
    }
}

data class CredentialSetQuery(
    val options: List<List<String>>,
    val required: Boolean = true
) : java.io.Serializable {
    init {
        validate()
    }

    private fun validate() {
        if (options.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("credential_set_query", "options"), null, CREDENTIAL_SET_QUERY_CLASS_NAME
            )
        }
        for (option in options) {
            if (option.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("credential_set_query", "options"), null, CREDENTIAL_SET_QUERY_CLASS_NAME
                )
            }
        }
    }

    internal fun validateCredentialIdReferences(credentialQueryIds: Set<String>) {
        for (option in options) {
            for (credentialQueryIdentifier in option) {
                if (!credentialQueryIds.contains(credentialQueryIdentifier)) {
                    throw OpenID4VPExceptions.InvalidData(
                        "credential_sets references unknown credential id '$credentialQueryIdentifier'",
                        CREDENTIAL_SET_QUERY_CLASS_NAME
                    )
                }
            }
        }
    }
}

sealed class ClaimValue : java.io.Serializable {
    data class StringValue(val value: String) : ClaimValue()
    data class LongValue(val value: Long) : ClaimValue()
    data class BoolValue(val value: Boolean) : ClaimValue()

    companion object {
        fun from(value: Any?): ClaimValue {
            return when (value) {
                is Boolean -> BoolValue(value)
                is Int -> LongValue(value.toLong())
                is Long -> LongValue(value)
                is String -> StringValue(value)
                else -> throw OpenID4VPExceptions.InvalidData(
                    "Claim value must be a string, integer, or boolean",
                    CLAIM_VALUE_CLASS_NAME
                )
            }
        }
    }
}

data class ClaimsQuery(
    val id: String? = null,
    val path: List<Any?>,
    val values: List<ClaimValue>? = null
) : java.io.Serializable {
    internal fun validate(isClaimSetsAvailable: Boolean) {
        if (isClaimSetsAvailable && id == null) {
            throw OpenID4VPExceptions.InvalidData(
                "Claims with claim_sets must have an id",
                CLAIMS_QUERY_CLASS_NAME
            )
        }

        id?.let {
            if (!VALID_ID_PATTERN.matches(it)) {
                throw OpenID4VPExceptions.InvalidData(
                    "Claims Query id must consist of alphanumeric, underscore or hyphen characters",
                    CLAIMS_QUERY_CLASS_NAME
                )
            }
        }

        if (path.isEmpty()) {
            throw OpenID4VPExceptions.InvalidInput(
                listOf("claims_query", "path"), null, CLAIMS_QUERY_CLASS_NAME
            )
        }

        values?.let {
            if (it.isEmpty()) {
                throw OpenID4VPExceptions.InvalidInput(
                    listOf("claims_query", "values"), null, CLAIMS_QUERY_CLASS_NAME
                )
            }
        }
    }
}