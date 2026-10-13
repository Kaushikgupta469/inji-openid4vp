package io.mosip.openID4VP.dcql.evaluator

import io.mosip.openID4VP.dcql.query.ClaimValue
import io.mosip.openID4VP.dcql.query.ClaimsQuery
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.CredentialSetQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.wallet.Credential

internal class DcqlEvaluator {

    fun evaluate(
        dcqlQuery: DCQLQuery,
        inputCredentials: List<Credential>
    ): MatchingCredentialsResult {
        val queryMatches = mutableMapOf<String, QueryMatchResult>()

        val credentialsByFormat = inputCredentials.groupBy { it.format.value }
        val credentialIdToCredential = inputCredentials.associateBy { it.credentialId }

        // Local caches
        val credentialsTagCache = mutableMapOf<String, TaggedCredential>()
        val processedCredentialsCache = mutableMapOf<String, ProcessedCredential>()
        val holderAlgorithmCache = mutableMapOf<String, String?>()

        for (credentialQuery in dcqlQuery.credentials) {
            // 1. Format check
            val formatMatchingCredentials = credentialsByFormat[credentialQuery.format]
            if (formatMatchingCredentials.isNullOrEmpty()) {
                queryMatches[credentialQuery.id] = QueryMatchResult(
                    failureReason = DCQLEvaluationErrorCodes.NO_MATCHING_FORMATS_FOUND,
                    allowMultipleCredentials = credentialQuery.multiple
                )
                continue
            }

            // 2. Cryptographic Holder Binding and Meta check
            val metaAndBindingMatchingIds = mutableListOf<String>()
            for (credential in formatMatchingCredentials) {
                val credentialId = credential.credentialId

                if (!credentialsTagCache.containsKey(credentialId)) {
                    credentialsTagCache[credentialId] = expandCredentialTag(credential)
                }

                val credentialTag = credentialsTagCache[credentialId] ?: continue

                val holderBindingAndMetaMatchSuccess = matchesCryptographicHolderBinding(
                    dcqlQueryRequestsCryptographicHolderBinding = credentialQuery.requireCryptographicHolderBinding,
                    walletCredential = credentialTag
                ) &&
                        matchesMeta(credentialQuery.meta, walletCredential = credentialTag) &&
                        canPreparePresentation(
                            credentialQuery.requireCryptographicHolderBinding,
                            credentialTag,
                            holderAlgorithmCache
                        )

                if (holderBindingAndMetaMatchSuccess) {
                    metaAndBindingMatchingIds.add(credentialId)
                }
            }

            if (metaAndBindingMatchingIds.isEmpty()) {
                queryMatches[credentialQuery.id] = QueryMatchResult(
                    failureReason = DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH,
                    allowMultipleCredentials = credentialQuery.multiple
                )
                continue
            }

            // 3. Claims level check
            val applicableInputCredentials = getProcessedCredentials(
                matchingIds = metaAndBindingMatchingIds,
                credentialIdToCredential = credentialIdToCredential,
                processedCache = processedCredentialsCache
            )

            queryMatches[credentialQuery.id] = evaluateCredentialQueryClaims(
                credentialQuery, applicableInputCredentials
            )
        }

        val credentialSetRequirements = buildCredentialSetRequirements(dcqlQuery)
        val success = isQuerySatisfied(queryMatches, credentialSetRequirements, dcqlQuery)

        return MatchingCredentialsResult(
            success = success,
            queryMatches = queryMatches,
            credentialSets = credentialSetRequirements
        )
    }

    private fun getProcessedCredentials(
        matchingIds: List<String>,
        credentialIdToCredential: Map<String, Credential>,
        processedCache: MutableMap<String, ProcessedCredential>
    ): List<ProcessedCredential> {
        val matchingIdsSet = matchingIds.toSet()
        val nonProcessedIds = matchingIdsSet.filter { !processedCache.containsKey(it) }

        if (nonProcessedIds.isNotEmpty()) {
            val newProcessed =
                convertToProcessedCredentials(nonProcessedIds, credentialIdToCredential)
            processedCache.putAll(newProcessed)
        }

        return matchingIds.mapNotNull { processedCache[it] }
    }

    private fun evaluateCredentialQueryClaims(
        credentialQuery: CredentialQuery,
        walletCredentials: List<ProcessedCredential>
    ): QueryMatchResult {
        if (credentialQuery.claims == null) {
            val matchingCredentials = walletCredentials.map {
                MatchingCredential(credentialId = it.credentialId, matchingClaims = emptyList())
            }
            return QueryMatchResult(
                matchingCredentials = matchingCredentials,
                allowMultipleCredentials = credentialQuery.multiple
            )
        }

        val matchingCredentials = mutableListOf<MatchingCredential>()
        val failedClaims = mutableListOf<ClaimFailure>()
        val failedClaimKeys = mutableSetOf<String>()
        var claimsCheckFailureReason: DCQLEvaluationErrorCodes? = null

        for (credential in walletCredentials) {
            val (matchingClaimsList, claimFailures, failureReason) = evaluateClaims(
                credentialQuery, credential
            )

            if (claimFailures.isEmpty()) {
                matchingCredentials.add(
                    MatchingCredential(
                        credentialId = credential.credentialId,
                        matchingClaims = matchingClaimsList
                    )
                )
            } else {
                if (claimsCheckFailureReason == null) {
                    claimsCheckFailureReason = failureReason
                }
                for (failure in claimFailures) {
                    val deduplicationKey =
                        "${failure.reason}:${failure.claim.path.joinToString(".")}"
                    if (failedClaimKeys.add(deduplicationKey)) {
                        failedClaims.add(failure)
                    }
                }
            }
        }

        if (matchingCredentials.isEmpty()) {
            return QueryMatchResult(
                failedClaims = failedClaims.ifEmpty { null },
                failureReason = claimsCheckFailureReason,
                allowMultipleCredentials = credentialQuery.multiple
            )
        }

        return QueryMatchResult(
            matchingCredentials = matchingCredentials,
            allowMultipleCredentials = credentialQuery.multiple
        )
    }

    private data class ClaimsEvaluationResult(
        val matchingClaims: List<ClaimsQuery>,
        val failedClaims: List<ClaimFailure>,
        val failureReason: DCQLEvaluationErrorCodes?
    )

    private fun evaluateClaims(
        credentialQuery: CredentialQuery,
        walletCredential: ProcessedCredential
    ): ClaimsEvaluationResult {
        val claims = credentialQuery.claims
            ?: return ClaimsEvaluationResult(emptyList(), emptyList(), null)

        if (credentialQuery.claimSets != null) {
            val failedClaimSetQuery = mutableListOf<ClaimFailure>()
            for (claimSetOption in credentialQuery.claimSets) {
                val requestedClaims = claims.filter { claimSetOption.contains(it.id ?: "") }
                val (matchingClaimsList, claimFailures) = checkClaims(
                    requestedClaims,
                    walletCredential
                )

                if (claimFailures.isEmpty()) {
                    return ClaimsEvaluationResult(matchingClaimsList, emptyList(), null)
                }
                failedClaimSetQuery.addAll(claimFailures)
            }
            return ClaimsEvaluationResult(
                emptyList(), failedClaimSetQuery,
                DCQLEvaluationErrorCodes.NO_CLAIMS_SET_OPTION_SATISFIED
            )
        }

        val (matchingClaimsList, claimFailures) = checkClaims(claims, walletCredential)
        if (claimFailures.isEmpty()) {
            return ClaimsEvaluationResult(matchingClaimsList, emptyList(), null)
        }
        return ClaimsEvaluationResult(
            emptyList(), claimFailures,
            DCQLEvaluationErrorCodes.REQUIRED_CLAIMS_NOT_SATISFIED
        )
    }

    private data class CheckClaimsResult(
        val matchingClaims: List<ClaimsQuery>,
        val failedClaims: List<ClaimFailure>
    )

    private fun checkClaims(
        claims: List<ClaimsQuery>,
        walletCredential: ProcessedCredential
    ): CheckClaimsResult {
        val matchingClaims = mutableListOf<ClaimsQuery>()
        val failedClaims = mutableListOf<ClaimFailure>()

        for (claimQuery in claims) {
            val resolved: Any? = try {
                when (walletCredential) {
                    is MdocProcessedCredential -> resolveClaimsPathPointer(
                        claimQuery.path, walletCredential.namespaces
                    )

                    is W3cProcessedCredential -> resolveClaimsPathPointer(
                        claimQuery.path, walletCredential.claims
                    )

                    is SdJwtProcessedCredential -> resolveClaimsPathPointer(
                        claimQuery.path, walletCredential.claims
                    )

                    else -> null
                }
            } catch (_: Exception) {
                null
            }

            if (resolved == null) {
                failedClaims.add(
                    ClaimFailure(
                        claimQuery,
                        DCQLEvaluationErrorCodes.CLAIM_UNAVAILABLE
                    )
                )
                continue
            }

            if (claimQuery.values != null && !matchesExpectedValues(resolved, claimQuery.values, pathHasWildcard = claimQuery.path.any { it == null })) {
                failedClaims.add(
                    ClaimFailure(
                        claimQuery,
                        DCQLEvaluationErrorCodes.CLAIM_VALUE_MISMATCH
                    )
                )
                continue
            }

            matchingClaims.add(claimQuery)
        }

        return CheckClaimsResult(matchingClaims, failedClaims)
    }

    private fun matchesExpectedValues(claimValue: Any, expectedValues: List<ClaimValue>, pathHasWildcard: Boolean): Boolean {
        val selectedValues: List<Any> =
            if (pathHasWildcard && claimValue is List<*>) claimValue.filterNotNull()
            else listOf(claimValue)
        if (selectedValues.isEmpty()) return false

        return selectedValues.any { selectedValue ->
            expectedValues.any { expected ->
                when (expected) {
                    is ClaimValue.StringValue -> (selectedValue as? String) == expected.value
                    is ClaimValue.LongValue -> {
                        when (selectedValue) {
                            is Int -> selectedValue.toLong() == expected.value
                            is Long -> selectedValue == expected.value
                            is Double -> selectedValue.toLong() == expected.value
                            is Number -> selectedValue.toLong() == expected.value
                            else -> false
                        }
                    }
                    is ClaimValue.BoolValue -> (selectedValue as? Boolean) == expected.value
                }
            }
        }
    }

    @Suppress("UNCHECKED_CAST")
    private fun matchesMeta(meta: Map<String, Any>, walletCredential: TaggedCredential): Boolean {
        if (meta.isEmpty()) return true

        return when (walletCredential) {
            is SdJwtTaggedCredential -> {
                val vctValues = meta["vct_values"] as? List<String> ?: return false
                vctValues.contains(walletCredential.vct)
            }

            is MdocTaggedCredential -> {
                val doctypeValue = meta["doctype_value"] as? String ?: return false
                walletCredential.doctype == doctypeValue
            }

            is W3cTaggedCredential -> {
                val typeValues = meta["type_values"] as? List<List<String>> ?: return false
                typeValues.any { requiredTypes ->
                    requiredTypes.all { walletCredential.types.contains(it) }
                }
            }

            else -> false
        }
    }

    private fun matchesCryptographicHolderBinding(
        dcqlQueryRequestsCryptographicHolderBinding: Boolean,
        walletCredential: TaggedCredential
    ): Boolean {
        return !dcqlQueryRequestsCryptographicHolderBinding || walletCredential.hasCryptographicHolderBinding
    }

    private fun buildCredentialSetRequirements(dcqlQuery: DCQLQuery): List<CredentialSetQuery> {
        return dcqlQuery.credentialSets
            ?: dcqlQuery.credentials.map {
                CredentialSetQuery(
                    options = listOf(listOf(it.id)),
                    required = true
                )
            }
    }

    private fun isQuerySatisfied(
        queryMatches: Map<String, QueryMatchResult>,
        credentialSets: List<CredentialSetQuery>,
        dcqlQuery: DCQLQuery
    ): Boolean {
        if (dcqlQuery.credentialSets == null) {
            return queryMatches.values.all { !it.matchingCredentials.isNullOrEmpty() }
        }

        for (credentialSet in credentialSets) {
            if (!credentialSet.required) continue

            val setIsSatisfied = credentialSet.options.any { option ->
                option.all { credentialQueryId ->
                    !queryMatches[credentialQueryId]?.matchingCredentials.isNullOrEmpty()
                }
            }

            if (!setIsSatisfied) return false
        }

        return true
    }
}
