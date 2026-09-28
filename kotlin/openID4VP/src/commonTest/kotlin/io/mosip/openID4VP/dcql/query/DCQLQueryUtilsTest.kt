package io.mosip.openID4VP.dcql.query

import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.DCQL_QUERY
import io.mosip.openID4VP.authorizationRequest.AuthorizationRequestFieldConstants.SCOPE

class `DCQLQueryUtilsTest` {

    @Test
    fun `should parse dcql query from json string`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to """
                {
                  "credentials": [
                    {"id": "cred1", "meta":{}, "format": "vc+sd-jwt", "claims": [{"path": ["given_name"]}]}
                  ]
                }
            """.trimIndent()
        )

        val result = parseAndValidateDcqlQuery(authorizationRequest)
        val query = assertIs<DCQLQuery>(result[AuthorizationRequestFieldConstants.DCQL_QUERY.value])

        assertEquals("cred1", query.credentials.first().id)
        assertEquals("vc+sd-jwt", query.credentials.first().format)
    }

    @Test
    fun `should parse dcql query from map`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to mapOf(
                "credentials" to listOf(
                    mapOf(
                        "id" to "cred1",
                        "format" to "mso_mdoc",
                        "meta" to mapOf("doctype_value" to "org.iso.18013.5.1.mDL")
                    )
                )
            )
        )

        val result = parseAndValidateDcqlQuery(authorizationRequest)
        val query = assertIs<DCQLQuery>(result[AuthorizationRequestFieldConstants.DCQL_QUERY.value])

        assertEquals(1, query.credentials.size)
        assertTrue(query.credentials.first().meta.containsKey("doctype_value"))
    }

    @Test
    fun `should parse claim path with array index`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to mapOf(
                "credentials" to listOf(
                    mapOf(
                        "id" to "employee-sd-jwt",
                        "format" to "vc+sd-jwt",
                        "meta" to emptyMap<String, Any>(),
                        "claims" to listOf(
                            mapOf("path" to listOf("degrees", 0, "type"))
                        )
                    )
                )
            )
        )

        val result = parseAndValidateDcqlQuery(authorizationRequest)
        val query = assertIs<DCQLQuery>(result[AuthorizationRequestFieldConstants.DCQL_QUERY.value])

        assertEquals(listOf("degrees", 0, "type"), query.credentials.first().claims?.first()?.path)
    }

    @Test
    fun `should throw when claim values contain nested arrays`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to """
                {
                  "credentials": [
                    {
                      "id": "tax-id",
                      "format": "vc+sd-jwt",
                      "meta": {},
                      "claims": [
                        {
                          "path": ["issuing_authority"],
                          "values": [["DE", "TelOrg"]]
                        }
                      ]
                    }
                  ]
                }
            """.trimIndent()
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(authorizationRequest)
        }

        assertOpenId4VPException(
            exception,
            "Claim value must be a string, integer, or boolean",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw missing input when dcql query field is absent`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            parseAndValidateDcqlQuery(mutableMapOf())
        }

        assertOpenId4VPException(
            exception,
            "Missing Input: authorizationRequest->dcql_query param is required",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `should throw invalid data when json is malformed`() {
        val authorizationRequest = mutableMapOf<String, Any>(
            AuthorizationRequestFieldConstants.DCQL_QUERY.value to "{\"credentials\":["
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(authorizationRequest)
        }

        assertTrue(exception.message!!.startsWith("Failed to parse dcql_query:"))
        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST, exception.errorCode)
    }

    @Test
    fun `rejects a request carrying both dcql_query and scope`() {
        val request = mutableMapOf<String, Any>(
            DCQL_QUERY.value to mapOf("credentials" to emptyList<Any>()),
            SCOPE.value to "openid"
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(request)
        }
        assertEquals(
            "The request contains both a dcql_query parameter and a scope parameter",
            exception.message
        )
    }

    @Test
    fun `rejects a dcql_query that is neither a string nor an object`() {
        val request = mutableMapOf<String, Any>(DCQL_QUERY.value to 42)

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(request)
        }
        assertEquals(
            "The dcql_query parameter must be a string or a JSON object",
            exception.message
        )
    }

    @Test
    fun `requires credentials on a dcql_query object`() {
        val request = mutableMapOf<String, Any>(DCQL_QUERY.value to mapOf("other" to "value"))

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            parseAndValidateDcqlQuery(request)
        }
        assertEquals("Missing Input: dcql_query->credentials param is required", exception.message)
    }

    @Test
    fun `requires an id on each credential query`() {
        val request = requestWithCredential(mapOf("format" to "vc+sd-jwt", "meta" to emptyMap<String, Any>()))

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            parseAndValidateDcqlQuery(request)
        }
        assertEquals("Missing Input: credential_query->id param is required", exception.message)
    }

    @Test
    fun `requires a format on each credential query`() {
        val request = requestWithCredential(mapOf("id" to "cred1", "meta" to emptyMap<String, Any>()))

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            parseAndValidateDcqlQuery(request)
        }
        assertEquals("Missing Input: credential_query->format param is required", exception.message)
    }

    @Test
    fun `defaults meta to empty map when absent`() {
        val request = requestWithCredential(mapOf("id" to "cred1", "format" to "vc+sd-jwt"))

        val query = assertIs<DCQLQuery>(parseAndValidateDcqlQuery(request)[DCQL_QUERY.value])
        assertTrue(query.credentials.single().meta.isEmpty())
    }

    @Test
    fun `rejects non-serializable value in meta`() {
        val request = requestWithCredential(
            mapOf(
                "id" to "cred1",
                "format" to "vc+sd-jwt",
                "meta" to mapOf("key" to object {})
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(request)
        }
        assertTrue(exception.message!!.contains("Non-serializable value"))
    }

    @Test
    fun `rejects non-serializable value in path`() {
        val request = requestWithCredential(
            mapOf(
                "id" to "cred1",
                "format" to "vc+sd-jwt",
                "meta" to emptyMap<String, Any>(),
                "claims" to listOf(mapOf("path" to listOf(object {})))
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(request)
        }
        assertTrue(exception.message!!.contains("Non-serializable value"))
    }

    @Test
    fun `requires a path on each claims query`() {
        val request = requestWithCredential(
            mapOf(
                "id" to "cred1",
                "format" to "vc+sd-jwt",
                "meta" to emptyMap<String, Any>(),
                "claims" to listOf(mapOf("id" to "name"))
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            parseAndValidateDcqlQuery(request)
        }
        assertEquals("Missing Input: claims_query->path param is required", exception.message)
    }

    @Test
    fun `requires options on each credential set query`() {
        val request = mutableMapOf<String, Any>(
            DCQL_QUERY.value to mapOf(
                "credentials" to listOf(
                    mapOf("id" to "cred1", "format" to "vc+sd-jwt", "meta" to emptyMap<String, Any>())
                ),
                "credential_sets" to listOf(mapOf("required" to true))
            )
        )

        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            parseAndValidateDcqlQuery(request)
        }
        assertEquals(
            "Missing Input: credential_set_query->options param is required",
            exception.message
        )
    }

    @Test
    fun `parses optional credential query fields`() {
        val request = requestWithCredential(
            mapOf(
                "id" to "cred1",
                "format" to "vc+sd-jwt",
                "meta" to mapOf("vct_values" to listOf("employee")),
                "multiple" to true,
                "require_cryptographic_holder_binding" to false,
                "claims" to listOf(mapOf("id" to "name", "path" to listOf("given_name"))),
                "claim_sets" to listOf(listOf("name"))
            )
        )

        val query = assertIs<DCQLQuery>(parseAndValidateDcqlQuery(request)[DCQL_QUERY.value])

        val credential = query.credentials.single()
        assertTrue(credential.multiple)
        assertEquals(false, credential.requireCryptographicHolderBinding)
        assertEquals(listOf(listOf("name")), credential.claimSets)
    }

    @Test
    fun `parses credential sets and defaults required to true`() {
        val request = mutableMapOf<String, Any>(
            DCQL_QUERY.value to mapOf(
                "credentials" to listOf(
                    mapOf("id" to "cred1", "format" to "vc+sd-jwt", "meta" to emptyMap<String, Any>())
                ),
                "credential_sets" to listOf(mapOf("options" to listOf(listOf("cred1"))))
            )
        )

        val query = assertIs<DCQLQuery>(parseAndValidateDcqlQuery(request)[DCQL_QUERY.value])

        assertTrue(query.credentialSets!!.single().required)
    }

    @Test
    fun `surfaces validation failures raised while parsing a json string`() {
        val request = mutableMapOf<String, Any>(
            DCQL_QUERY.value to """{"credentials": [{"id": "not valid!", "format": "vc+sd-jwt", "meta": {}}]}"""
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            parseAndValidateDcqlQuery(request)
        }
        assertEquals(
            "Credential Query id must consist of alphanumeric, underscore or hyphen characters",
            exception.message
        )
    }

    private fun requestWithCredential(credential: Map<String, Any>) = mutableMapOf<String, Any>(
        DCQL_QUERY.value to mapOf("credentials" to listOf(credential))
    )
}
