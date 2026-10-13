package io.mosip.openID4VP.dcql.evaluator

import io.mockk.every
import io.mockk.mockkObject
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.common.MdocCredentialUtils
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.dcql.query.ClaimsQuery
import io.mosip.openID4VP.dcql.query.CredentialQuery
import io.mosip.openID4VP.dcql.query.DCQLQuery
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.dcql.evaluator.DCQLTestFixtures.sdJwtCredential
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.dcql.query.ClaimValue
import io.mosip.openID4VP.dcql.query.CredentialSetQuery
import io.mosip.openID4VP.wallet.Credential
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.UnicodeString
import io.mockk.mockkObject
import io.mosip.openID4VP.common.JsonLDProcessor
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.taggedCbor24
import jakarta.json.Json as JakartaJson
import jakarta.json.JsonArray

class DcqlEvaluatorTest {

    private val evaluator = DcqlEvaluator()

    private val encoder = Base64.getUrlEncoder().withoutPadding()

    @BeforeTest
    fun setUp() {
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers { encoder.encodeToString(firstArg<ByteArray>()) }
        mockkObject(JsonLDProcessor)

        mockkObject(MdocCredentialUtils)
        every { MdocCredentialUtils.getMdocDocType(any<String>(), any()) } returns "org.iso.18013.5.1.mDL"

        mockkStatic(::decodeCbor)
        every { decodeCbor(any())} returns  DCQLTestFixtures.getDecodedMdoc()
    }

    @AfterTest
    fun tearDown() {
        unmockkAll()
    }

    @Test
    fun `should match sd-jwt credential by format and vct`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.sdJwtCredential(id = "sdjwt-1")))

        assertTrue(result.success)
        assertEquals(
            listOf("sdjwt-1"),
            result.queryMatches["employee-card"]?.matchingCredentials?.map { it.credentialId }
        )
    }

    @Test
    fun `should match mdoc credential by doctype`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.mdocCredential("mdoc-1")))

        assertTrue(result.success)
        assertEquals("mdoc-1", result.queryMatches["mobile-id"]?.matchingCredentials?.first()?.credentialId)
    }

    @Test
    fun `should match claims by nested path including null`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "w3c-card",
                    format = FormatType.LDP_VC.value,
                    claims = listOf(
                        ClaimsQuery(id = "given-name", path = listOf("credentialSubject", "given_name"))
                    )
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.w3cCredential(id = "ldp-1")))

        assertTrue(result.success)
        assertEquals(1, result.queryMatches["w3c-card"]?.matchingCredentials?.first()?.matchingClaims?.size)
    }
    @Test
    fun `should match sd-jwt claims by array index path`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-sd-jwt",
                    format = FormatType.VC_SD_JWT.value,
                    claims = listOf(
                        ClaimsQuery(path = listOf("degrees", 0, "type"))
                    )
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(sdJwtCredential(id = "sdjwt-1")))

        assertTrue(result.success)
        assertEquals(1, result.queryMatches["employee-sd-jwt"]?.matchingCredentials?.first()?.matchingClaims?.size)
    }

    @Test
    fun `should return failure with meta mismatch reason when vct does not match`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                DCQLTestFixtures.sdJwtCredential(
                    id = "sdjwt-1",
                    vct = "https://example.com/other"
                )
            )
        )

        assertFalse(result.success)
        assertNull(result.queryMatches["employee-card"]?.matchingCredentials)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches["employee-card"]?.failureReason
        )
    }

    @Test
    fun `should return failure with no matching formats when format does not match`() {
        val query = DCQLQuery(
            credentials = listOf(CredentialQuery(id = "employee-card", format = FormatType.VC_SD_JWT.value))
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.mdocCredential("mdoc-1")))

        assertFalse(result.success)
        assertNull(result.queryMatches["employee-card"]?.matchingCredentials)
        assertEquals(
            DCQLEvaluationErrorCodes.NO_MATCHING_FORMATS_FOUND.value,
            result.queryMatches["employee-card"]?.failureReason
        )
    }

    @Test
    fun `should return multiple matching credentials when multiple is true`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    multiple = true,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                DCQLTestFixtures.sdJwtCredential(id = "sdjwt-1"),
                DCQLTestFixtures.sdJwtCredential(id = "sdjwt-2")
            )
        )

        assertTrue(result.success)
        assertEquals(2, result.queryMatches["employee-card"]?.matchingCredentials?.size)
        assertTrue(result.queryMatches["employee-card"]?.allowMultipleCredentials == true)
    }

    @Test
    fun `should match sd-jwt credential with empty meta`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "any-sdjwt",
                    format = FormatType.VC_SD_JWT.value
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(DCQLTestFixtures.sdJwtCredential(id = "sdjwt-1")))

        assertTrue(result.success)
        assertEquals("sdjwt-1", result.queryMatches["any-sdjwt"]?.matchingCredentials?.first()?.credentialId)
    }

    @Test
    fun `should fail when holder binding is required but credential has no cnf`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "bound-card",
                    format = FormatType.VC_SD_JWT.value,
                    requireCryptographicHolderBinding = true,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(DCQLTestFixtures.sdJwtCredential(id = "sdjwt-no-cnf", holderBinding = false))
        )

        assertFalse(result.success)
        assertNull(result.queryMatches["bound-card"]?.matchingCredentials)
    }

    @Test
    fun `should evaluate multiple credential queries independently`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "sdjwt-query",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to listOf("https://example.com/employee"))
                ),
                CredentialQuery(
                    id = "mdoc-query",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                DCQLTestFixtures.sdJwtCredential(id = "sdjwt-1"),
                DCQLTestFixtures.mdocCredential("mdoc-1")
            )
        )

        assertTrue(result.success)
        assertEquals(2, result.queryMatches.size)
        assertEquals("sdjwt-1", result.queryMatches["sdjwt-query"]?.matchingCredentials?.first()?.credentialId)
        assertEquals("mdoc-1", result.queryMatches["mdoc-query"]?.matchingCredentials?.first()?.credentialId)
    }

    @Test
    fun `reports claim_unavailable against the claim that could not be resolved`() {
        val query = singleQuery(claims = listOf(ClaimsQuery(path = listOf("absent_claim"))))

        val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", mapOf("vct" to "employee"))))

        assertFalse(result.success)
        val match = result.queryMatches.getValue("employee-card")
        val failure = match.failedClaims?.single()
        assertEquals(DCQLEvaluationErrorCodes.CLAIM_UNAVAILABLE.value, failure?.reason)
        assertEquals(listOf("absent_claim"), failure?.claim?.path)
        assertEquals(
            DCQLEvaluationErrorCodes.REQUIRED_CLAIMS_NOT_SATISFIED.value,
            match.failureReason
        )
        assertNull(match.matchingCredentials)
    }

    @Test
    fun `reports required_claims_not_satisfied when only some claims resolve`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(path = listOf("given_name")),
                ClaimsQuery(path = listOf("absent_claim"))
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("given_name" to "Alice")))
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.REQUIRED_CLAIMS_NOT_SATISFIED.value,
            result.queryMatches.getValue("employee-card").failureReason
        )
    }

    @Test
    fun `deduplicates identical claim failures across credentials`() {
        val query = singleQuery(claims = listOf(ClaimsQuery(path = listOf("absent_claim"))))

        val result = evaluator.evaluate(
            query,
            listOf(
                sdJwt("sdjwt-1", mapOf("given_name" to "Alice")),
                sdJwt("sdjwt-2", mapOf("given_name" to "Bob"))
            )
        )

        assertEquals(1, result.queryMatches.getValue("employee-card").failedClaims?.size)
    }

    @Test
    fun `matches a string claim against expected values`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(
                    path = listOf("given_name"),
                    values = listOf(ClaimValue.StringValue("Alice"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("given_name" to "Alice")))
        )

        assertTrue(result.success)
    }

    @Test
    fun `matches null-path selected values when any element equals an expected value`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(
                    path = listOf("credentialSubject", "gender", null, "value"),
                    values = listOf(ClaimValue.StringValue("MLE"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                sdJwt(
                    "sdjwt-1",
                    mapOf(
                        "credentialSubject" to mapOf(
                            "gender" to listOf(
                                mapOf("language" to "eng", "value" to "MLE"),
                                mapOf("language" to "fra", "value" to "MLE"),
                                mapOf("language" to "ara", "value" to "MLE")
                            )
                        )
                    )
                )
            )
        )

        assertTrue(result.success)
    }

    @Test
    fun `rejects null-path selected values when none equal an expected value`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(
                    path = listOf("credentialSubject", "gender", null, "value"),
                    values = listOf(ClaimValue.StringValue("FEM"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                sdJwt(
                    "sdjwt-1",
                    mapOf(
                        "credentialSubject" to mapOf(
                            "gender" to listOf(
                                mapOf("language" to "eng", "value" to "MLE"),
                                mapOf("language" to "fra", "value" to "MLE")
                            )
                        )
                    )
                )
            )
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CLAIM_VALUE_MISMATCH.value,
            result.queryMatches.getValue("employee-card").failedClaims?.single()?.reason
        )
    }

    @Test
    fun `does not match an array claim as a whole against a scalar expected value`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(
                    path = listOf("nationalities"),
                    values = listOf(ClaimValue.StringValue("DE"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("nationalities" to listOf("DE", "FR"))))
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CLAIM_VALUE_MISMATCH.value,
            result.queryMatches.getValue("employee-card").failedClaims?.single()?.reason
        )
    }

    @Test
    fun `matches any array element when path ends with null and values are present`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(
                    path = listOf("nationalities", null),
                    values = listOf(ClaimValue.StringValue("DE"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("nationalities" to listOf("DE", "FR"))))
        )

        assertTrue(result.success)
    }

    @Test
    fun `matches nested null-path selected values against expected values`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(
                    path = listOf("degrees", null, "subjects", null, "name"),
                    values = listOf(ClaimValue.StringValue("Physics"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                sdJwt(
                    "sdjwt-1",
                    mapOf(
                        "degrees" to listOf(
                            mapOf(
                                "subjects" to listOf(
                                    mapOf("name" to "Math"),
                                    mapOf("name" to "Physics")
                                )
                            ),
                            mapOf(
                                "subjects" to listOf(mapOf("name" to "Chemistry"))
                            )
                        )
                    )
                )
            )
        )

        assertTrue(result.success)
    }

    @Test
    fun `reports claim_value_not_matching when no expected value matches`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(
                    path = listOf("given_name"),
                    values = listOf(ClaimValue.StringValue("Bob"))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("given_name" to "Alice")))
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CLAIM_VALUE_MISMATCH.value,
            result.queryMatches.getValue("employee-card").failedClaims?.single()?.reason
        )
    }

    @Test
    fun `matches numeric claims regardless of the parsed number type`() {
        val cases = listOf(
            mapOf("age" to 30) to 30L,
            mapOf("age" to 9_000_000_000L) to 9_000_000_000L,
            mapOf("age" to 30.0) to 30L
        )

        cases.forEach { (payload, expected) ->
            val query = singleQuery(
                claims = listOf(
                    ClaimsQuery(path = listOf("age"), values = listOf(ClaimValue.LongValue(expected)))
                )
            )

            val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", payload)))

            assertTrue(result.success, "payload=$payload")
        }
    }

    @Test
    fun `matches a boolean claim against expected values`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(path = listOf("is_active"), values = listOf(ClaimValue.BoolValue(true)))
            )
        )

        val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", mapOf("is_active" to true))))

        assertTrue(result.success)
    }

    @Test
    fun `does not match a boolean expectation against a non-boolean claim`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(path = listOf("is_active"), values = listOf(ClaimValue.BoolValue(true)))
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("is_active" to "yes")))
        )

        assertFalse(result.success)
    }

    @Test
    fun `does not match a numeric expectation against a non-numeric claim`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(path = listOf("age"), values = listOf(ClaimValue.LongValue(30L)))
            )
        )

        val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", mapOf("age" to "thirty"))))

        assertFalse(result.success)
    }

    @Test
    fun `satisfies a credential query via the first usable claim_sets option`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(id = "name", path = listOf("given_name")),
                ClaimsQuery(id = "country", path = listOf("issuing_country"))
            ),
            claimSets = listOf(listOf("name"), listOf("country"))
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("given_name" to "Alice")))
        )

        assertTrue(result.success)
        assertEquals(
            listOf("name"),
            result.queryMatches.getValue("employee-card")
                .matchingCredentials?.single()?.matchingClaims?.map { it.id }
        )
    }

    @Test
    fun `falls back to a later claim_sets option when the first is unsatisfied`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(id = "absent", path = listOf("absent_claim")),
                ClaimsQuery(id = "name", path = listOf("given_name"))
            ),
            claimSets = listOf(listOf("absent"), listOf("name"))
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("given_name" to "Alice")))
        )

        assertTrue(result.success)
        assertEquals(
            listOf("name"),
            result.queryMatches.getValue("employee-card")
                .matchingCredentials?.single()?.matchingClaims?.map { it.id }
        )
    }

    @Test
    fun `reports no_claims_set_option_satisfied when every option fails`() {
        val query = singleQuery(
            claims = listOf(
                ClaimsQuery(id = "absent", path = listOf("absent_claim")),
                ClaimsQuery(id = "other", path = listOf("other_absent"))
            ),
            claimSets = listOf(listOf("absent"), listOf("other"))
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("given_name" to "Alice")))
        )

        assertFalse(result.success)
        val match = result.queryMatches.getValue("employee-card")
        assertEquals(DCQLEvaluationErrorCodes.NO_CLAIMS_SET_OPTION_SATISFIED.value, match.failureReason)
        assertEquals(2, match.failedClaims?.size)
    }

    @Test
    fun `fails when a required credential_set has no satisfiable option`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "employee-card", format = FormatType.VC_SD_JWT.value),
                CredentialQuery(id = "mobile-id", format = FormatType.MSO_MDOC.value)
            ),
            credentialSets = listOf(CredentialSetQuery(options = listOf(listOf("mobile-id"))))
        )

        val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", mapOf("vct" to "employee"))))

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.NO_MATCHING_FORMATS_FOUND.value,
            result.queryMatches.getValue("mobile-id").failureReason
        )
    }

    @Test
    fun `succeeds when only an optional credential_set is unsatisfied`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "employee-card", format = FormatType.VC_SD_JWT.value),
                CredentialQuery(id = "mobile-id", format = FormatType.MSO_MDOC.value)
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf("employee-card"))),
                CredentialSetQuery(options = listOf(listOf("mobile-id")), required = false)
            )
        )

        val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", mapOf("vct" to "employee"))))

        assertTrue(result.success)
    }

    @Test
    fun `satisfies a required credential_set through any one option`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(id = "employee-card", format = FormatType.VC_SD_JWT.value),
                CredentialQuery(id = "mobile-id", format = FormatType.MSO_MDOC.value)
            ),
            credentialSets = listOf(
                CredentialSetQuery(options = listOf(listOf("mobile-id"), listOf("employee-card")))
            )
        )

        val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", mapOf("vct" to "employee"))))

        assertTrue(result.success)
    }

    @Test
    fun `defaults credential_sets to one required set per credential query`() {
        val query = singleQuery()

        val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", mapOf("vct" to "employee"))))

        assertEquals(
            listOf(CredentialSetQuery(options = listOf(listOf("employee-card")), required = true)),
            result.credentialSets
        )
    }

    @Test
    fun `rejects a credential without holder binding when the query requires it`() {
        val query = singleQuery()

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("vct" to "employee"), holderBinding = false))
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches.getValue("employee-card").failureReason
        )
    }

    @Test
    fun `accepts a credential without holder binding when the query does not require it`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    requireCryptographicHolderBinding = false
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("vct" to "employee"), holderBinding = false))
        )

        assertTrue(result.success)
    }

    @Test
    fun `carries the multiple flag onto the query match result`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    multiple = true
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(
                sdJwt("sdjwt-1", mapOf("vct" to "employee")),
                sdJwt("sdjwt-2", mapOf("vct" to "employee"))
            )
        )

        val match = result.queryMatches.getValue("employee-card")
        assertTrue(match.allowMultipleCredentials)
        assertEquals(listOf("sdjwt-1", "sdjwt-2"), match.matchingCredentials?.map { it.credentialId })
    }

    @Test
    fun `keeps the multiple flag on a failed query match`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    multiple = true
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(sdJwt("sdjwt-1", mapOf("vct" to "employee"))))

        assertTrue(result.queryMatches.getValue("mobile-id").allowMultipleCredentials)
    }

    private fun singleQuery(
        claims: List<ClaimsQuery>? = null,
        claimSets: List<List<String>>? = null
    ) = DCQLQuery(
        credentials = listOf(
            CredentialQuery(
                id = "employee-card",
                format = FormatType.VC_SD_JWT.value,
                claims = claims,
                claimSets = claimSets
            )
        )
    )

    @Test
    fun `reports an unavailable claim when resolving the path throws`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    claims = listOf(ClaimsQuery(path = listOf("degrees", null, "type")))
                )
            )
        )

        val result = evaluator.evaluate(
            query,
            listOf(sdJwt("sdjwt-1", mapOf("degrees" to listOf("B.Tech", "M.S."))))
        )

        assertFalse(result.success)
        val match = result.queryMatches.getValue("employee-card")
        assertNull(match.matchingCredentials)
        assertEquals(
            DCQLEvaluationErrorCodes.REQUIRED_CLAIMS_NOT_SATISFIED.value,
            match.failureReason
        )
        val failedClaim = match.failedClaims?.single()
        assertEquals(DCQLEvaluationErrorCodes.CLAIM_UNAVAILABLE.value, failedClaim?.reason)
        assertEquals(listOf("degrees", null, "type"), failedClaim?.claim?.path)
    }

    private fun sdJwt(
        id: String,
        claims: Map<String, Any>,
        holderBinding: Boolean = true
    ): Credential {
        val payload = claims.toMutableMap()
        if (holderBinding) {
            payload["cnf"] = mapOf("kid" to "did:example:holder#key-1")
        }
        val header = encoder.encodeToString(
            getObjectMapper().writeValueAsBytes(mapOf("alg" to "none"))
        )
        val body = encoder.encodeToString(getObjectMapper().writeValueAsBytes(payload))
        return Credential(FormatType.VC_SD_JWT, "$header.$body.signature", id)
    }

    @Test
    fun `matches a w3c credential whose expanded types satisfy type_values`() {
        expandedTypes("VerifiableCredential", "EmployeeCredential")

        val result = evaluator.evaluate(
            w3cQuery(listOf(listOf("VerifiableCredential", "EmployeeCredential"))),
            listOf(w3cCredential())
        )

        assertTrue(result.success)
        assertEquals(
            listOf("ldp-1"),
            result.queryMatches.getValue("w3c-card").matchingCredentials?.map { it.credentialId }
        )
    }

    @Test
    fun `matches a w3c credential through any satisfied type_values option`() {
        expandedTypes("VerifiableCredential", "EmployeeCredential")

        val result = evaluator.evaluate(
            w3cQuery(listOf(listOf("UnrelatedCredential"), listOf("EmployeeCredential"))),
            listOf(w3cCredential())
        )

        assertTrue(result.success)
    }

    @Test
    fun `rejects a w3c credential missing a required type`() {
        expandedTypes("VerifiableCredential")

        val result = evaluator.evaluate(
            w3cQuery(listOf(listOf("VerifiableCredential", "EmployeeCredential"))),
            listOf(w3cCredential())
        )

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CRYPTOGRAPHIC_HOLDER_BINDING_OR_META_FILTER_MISMATCH.value,
            result.queryMatches.getValue("w3c-card").failureReason
        )
    }

    @Test
    fun `rejects a w3c credential when type_values is not a list`() {
        expandedTypes("VerifiableCredential")

        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "w3c-card",
                    format = FormatType.LDP_VC.value,
                    meta = mapOf("type_values" to "VerifiableCredential")
                )
            )
        )

        assertFalse(evaluator.evaluate(query, listOf(w3cCredential())).success)
    }

    @Test
    fun `treats a credential with no expanded types as unmatched`() {
        every { JsonLDProcessor.expand(any()) } returns JakartaJson.createArrayBuilder().build()

        assertFalse(
            evaluator.evaluate(
                w3cQuery(listOf(listOf("EmployeeCredential"))),
                listOf(w3cCredential())
            ).success
        )
    }

    @Test
    fun `treats a credential whose expansion omits @type as unmatched`() {
        every { JsonLDProcessor.expand(any()) } returns JakartaJson.createArrayBuilder()
            .add(JakartaJson.createObjectBuilder().add("@id", "urn:vc:1"))
            .build()

        assertFalse(
            evaluator.evaluate(
                w3cQuery(listOf(listOf("EmployeeCredential"))),
                listOf(w3cCredential())
            ).success
        )
    }

    @Test
    fun `treats a credential whose expansion fails as unmatched`() {
        every { JsonLDProcessor.expand(any()) } throws RuntimeException("context unreachable")

        assertFalse(
            evaluator.evaluate(
                w3cQuery(listOf(listOf("EmployeeCredential"))),
                listOf(w3cCredential())
            ).success
        )
    }

    @Test
    fun `matches a w3c credential on claims when no meta filter is given`() {
        expandedTypes("VerifiableCredential")

        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "w3c-card",
                    format = FormatType.LDP_VC.value,
                    claims = listOf(
                        ClaimsQuery(
                            path = listOf("credentialSubject", "given_name"),
                            values = listOf(ClaimValue.StringValue("Alice"))
                        )
                    )
                )
            )
        )

        assertTrue(evaluator.evaluate(query, listOf(w3cCredential())).success)
    }

    @Test
    fun `matches mdoc claims addressed through namespace and element identifier`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.mDL"),
                    claims = listOf(
                        ClaimsQuery(
                            path = listOf("org.iso.18013.5.1", "given_name"),
                            values = listOf(ClaimValue.StringValue("Alice"))
                        )
                    )
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(mdocCredential()))

        assertTrue(result.success)
        assertEquals(
            listOf("mdoc-1"),
            result.queryMatches.getValue("mobile-id").matchingCredentials?.map { it.credentialId }
        )
    }

    @Test
    fun `reports an unavailable mdoc claim for an unknown element identifier`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    claims = listOf(ClaimsQuery(path = listOf("org.iso.18013.5.1", "absent")))
                )
            )
        )

        val result = evaluator.evaluate(query, listOf(mdocCredential()))

        assertFalse(result.success)
        assertEquals(
            DCQLEvaluationErrorCodes.CLAIM_UNAVAILABLE.value,
            result.queryMatches.getValue("mobile-id").failedClaims?.single()?.reason
        )
    }

    @Test
    fun `rejects an mdoc credential whose doctype does not match`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to "org.iso.18013.5.1.other")
                )
            )
        )

        assertFalse(evaluator.evaluate(query, listOf(mdocCredential())).success)
    }

    @Test
    fun `rejects an mdoc credential when doctype_value is not a string`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "mobile-id",
                    format = FormatType.MSO_MDOC.value,
                    meta = mapOf("doctype_value" to listOf("org.iso.18013.5.1.mDL"))
                )
            )
        )

        assertFalse(evaluator.evaluate(query, listOf(mdocCredential())).success)
    }

    @Test
    fun `rejects an sd-jwt credential when vct_values is not a list`() {
        val query = DCQLQuery(
            credentials = listOf(
                CredentialQuery(
                    id = "employee-card",
                    format = FormatType.VC_SD_JWT.value,
                    meta = mapOf("vct_values" to "https://example.com/employee")
                )
            )
        )

        assertFalse(
            evaluator.evaluate(query, listOf(DCQLTestFixtures.sdJwtCredential("sdjwt-1"))).success
        )
    }

    private fun expandedTypes(vararg types: String) {
        val typeArray = JakartaJson.createArrayBuilder()
        types.forEach { typeArray.add(it) }
        val expanded: JsonArray = JakartaJson.createArrayBuilder()
            .add(JakartaJson.createObjectBuilder().add("@type", typeArray))
            .build()
        every { JsonLDProcessor.expand(any()) } returns expanded
    }

    private fun w3cQuery(typeValues: List<List<String>>) = DCQLQuery(
        credentials = listOf(
            CredentialQuery(
                id = "w3c-card",
                format = FormatType.LDP_VC.value,
                meta = mapOf("type_values" to typeValues)
            )
        )
    )

    private fun w3cCredential() = Credential(
        format = FormatType.LDP_VC,
        data = mapOf(
            "type" to listOf("VerifiableCredential", "EmployeeCredential"),
            "credentialSubject" to mapOf("given_name" to "Alice", "id" to "did:example:holder")
        ),
        credentialId = "ldp-1"
    )

    private fun element(identifier: String, value: DataItem): DataItem =
        taggedCbor24(CborMap().apply {
            put(UnicodeString("elementIdentifier"), UnicodeString(identifier))
            put(UnicodeString("elementValue"), value)
        })

    private fun mdocCredential(): Credential {
        val items = CborArray().apply {
            add(element("given_name", UnicodeString("Alice")))
            add(element("family_name", UnicodeString("Jones")))
        }
        val root = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("org.iso.18013.5.1.mDL"))
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("nameSpaces"), CborMap().apply {
                    put(UnicodeString("org.iso.18013.5.1"), items)
                })
            })
        }
        every { decodeCbor(any()) } returns root
        return Credential(
            format = FormatType.MSO_MDOC,
            data = encoder.encodeToString(encodeCbor(root)),
            credentialId = "mdoc-1"
        )
    }
}
