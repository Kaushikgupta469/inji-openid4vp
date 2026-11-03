package io.mosip.openID4VP.common

import com.fasterxml.jackson.annotation.JsonProperty
import com.nimbusds.jose.jwk.Curve
import io.mockk.*
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.constants.HttpMethod
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.networkManager.NetworkManagerClient
import io.mosip.openID4VP.networkManager.NetworkResponse
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.vercred.vcverifier.keyResolver.types.did.DidPublicKeyResolver
import kotlin.test.*
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import io.mosip.openID4VP.constants.FormatType
import java.security.MessageDigest
import kotlin.test.assertNull
import java.security.PublicKey

// Test helper: Creates a PublicKey with predictable class name for testing unsupported algorithms
class TestPublicKey(val keyAlgorithm: String) : PublicKey {
    override fun getAlgorithm(): String = keyAlgorithm
    override fun getEncoded(): ByteArray = byteArrayOf()
    override fun getFormat(): String = "TEST"
}

class UtilsTest {

    private val encoder = Base64.getUrlEncoder().withoutPadding()
    private val className = "UtilsTest"

    @BeforeTest
    fun mockBase64() {
        unmockkAll()
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers { encoder.encodeToString(firstArg<ByteArray>()) }
    }

    @AfterTest
    fun unmock() {
        unmockkAll()
    }

    @Test
    fun `isValidUrl should return true for valid URLs per RFC 3986`() {
        val validUrls = listOf(
            "https://example.com/path?query=value#fragment",
            // RFC 3986 structure: port + multi-segment path + query + fragment
            "https://example.com:8042/over/there?name=ferret#nose",
            // percent-encoded octets in path and query
            "https://example.com/a%20b?q=hello%20world",
            // empty path segment
            "https://example.com//empty/seg",
            // '/', '?' and '@' allowed within query and fragment
            "https://example.com/p?a=1/2&b=x?y#f/g?h"
        )

        validUrls.forEach { url -> assertTrue(isValidUrl(url), "expected valid: $url") }
    }

    @Test
    fun `isValidUrl should return false for invalid URL`() {

        val testUrls = listOf(
            "www.example.com",
            "http://example.com/space here",
            "http://",
            "https://example",
            "http://example.com/file%/name",
            "http://example.com:99999",
            "http:///example.com",
            "http://example.com/search?q=hello%20world#@fragment",
            "http://:8080",
            "",
            "https://example.com/invalid|character",
            // non-https scheme is rejected even with valid RFC 3986 structure
            "foo://example.com:8042/over/there?name=ferret#nose",
            // malformed percent-encoding (not followed by two hex digits)
            "https://example.com/file%/name",
            // whitespace is not allowed
            "https://example.com/space here",
            // trailing newline must not be accepted
            "https://example.com/path\n"
        )

        testUrls.forEach { url -> assertFalse(isValidUrl(url), "expected invalid: $url") }
    }

    @Test
    fun `convertJsonToMap should correctly parse JSON string`() {
        val json = "{\"key\":\"value\"}"
        val result = convertJsonToMap(json)
        assertEquals("value", result["key"])
    }

    @Test
    fun `isJWT should return true for valid JWT`() {
        val jwt = "header.payload.signature"
        assertTrue(isJWS(jwt))
    }

    @Test
    fun `isJWT should return false for invalid JWT`() {
        val jwt = "invalid.jwt"
        assertFalse(isJWS(jwt))
    }

    @Test
    fun `determineHttpMethod should return correct HTTP method`() {
        assertEquals(HttpMethod.GET, determineHttpMethod("get"))
        assertEquals(HttpMethod.POST, determineHttpMethod("post"))
    }

    @Test
    fun `determineHttpMethod should throw exception for unsupported method`() {
        assertFailsWith<IllegalArgumentException> {
            determineHttpMethod("put")
        }
    }

    @Test
    fun `getStringValue should return correct string value from map`() {
        val map = mapOf("key" to "value")
        assertEquals("value", getStringValue(map, "key"))
        assertNull(getStringValue(map, "nonexistent"))
    }

    internal data class MockDataClass(
        val key: String,
        @JsonProperty("key_with_more_than_one_word")
        val keyWithMoreThanOneWord: String,
        @JsonProperty("nullable_field")
        val nullableField: String? = null,
    )

    @Test

    fun `should serialize data class instance to JSON with all properties specified`() {
        val mockDataClass = MockDataClass(
            key = "id_credential",
            keyWithMoreThanOneWord = "ldp_vp",
            nullableField = "value",
        )

        val descriptorMapJson = encodeToJsonString<MockDataClass>(
            mockDataClass,
            "mockDataClass",
            "UtilsTest"
        )
        "{\"key\":\"id_credential\",\"number\":1,\"key_with_more_than_one_word\":\"ldp_vp\"}"

        assertEquals(
            "{\"key\":\"id_credential\",\"key_with_more_than_one_word\":\"ldp_vp\",\"nullable_field\":\"value\"}",
            descriptorMapJson
        )
    }

    @Test
    fun `should serialize data class without nullable fields to JSON successfully`() {
        val mockDataClass = MockDataClass(
            key = "id_credential",
            keyWithMoreThanOneWord = "ldp_vp",
        )

        val descriptorMapJson = encodeToJsonString<MockDataClass>(
            mockDataClass,
            "mockDataClass",
            "UtilsTest"
        )

        assertEquals(
            "{\"key\":\"id_credential\",\"key_with_more_than_one_word\":\"ldp_vp\"}",
            descriptorMapJson
        )
    }

    @Test
    fun toHex_emptyByteArray_returnsEmptyString() {
        val emptyArray = ByteArray(0)
        assertEquals("", emptyArray.toHex())
    }

    @Test
    fun toHex_simpleByteArray_returnsCorrectHexString() {
        val bytes = byteArrayOf(10, 20, 30, 40, 50)
        assertEquals("0a141e2832", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithSmallValues_includesLeadingZeros() {
        val bytes = byteArrayOf(0, 1, 15)
        assertEquals("00010f", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithNegativeValues_handlesCorrectly() {
        val bytes = byteArrayOf(-1, -128)
        assertEquals("ff80", bytes.toHex())
    }

    @Test
    fun toHex_byteArrayWithMixedValues_convertsCorrectly() {
        val bytes = byteArrayOf(0, 15, 16, 127, -128, -1)
        assertEquals("000f107f80ff", bytes.toHex())
    }

    @Test
    fun testResolveFromJwksUri() {
        val jwksUri = "https://mock-verifier.com/.well-known/jwks.json"
        val keyId = "f4a0c7f3f1b1e3a1b1e3a1b1e3a1b1e3a1b1e3a1b"
        mockkObject(NetworkManagerClient)
        val mockJwksResponse = """
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "x": "-Fy3lMapzR3wpaYNCFq29GDEn_NoR3pBsc511q1Cxqw",
                        "alg": "EdDSA",
                        "kid": "f4a0c7f3f1b1e3a1b1e3a1b1e3a1b1e3a1b1e3a1b",
                        "use": "sig"
                    }
                ]
            }
        """.trimIndent()
        every {
            NetworkManagerClient.sendHTTPRequest(jwksUri, HttpMethod.GET)
        } returns NetworkResponse(
            200, mockJwksResponse,
            headers = mapOf()
        )

        val publicKey = resolveJwksFromUri(jwksUri, keyId)

        assertNotNull(publicKey)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg honours an explicit alg on the confirmation jwk`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("kty" to "EC", "alg" to "ES512"))))

        val (jwkJson, alg) = resolveSdJwtKeyAndAlg(credential, className)

        assertEquals("ES512", alg)
        assertTrue(jwkJson.contains("\"kty\":\"EC\""))
    }

    @Test
    fun `resolveSdJwtKeyAndAlg infers the algorithm from kty and crv`() {
        val cases = mapOf(
            ("OKP" to "Ed25519") to "EdDSA",
            ("EC" to "P-256") to "ES256",
            ("EC" to "P-384") to "ES384",
            ("EC" to "P-521") to "ES512",
            ("EC" to "secp256k1") to "ES256K"
        )

        cases.forEach { (key, expectedAlg) ->
            val credential = sdJwt(
                mapOf("cnf" to mapOf("jwk" to mapOf("kty" to key.first, "crv" to key.second)))
            )
            assertEquals(
                expectedAlg,
                resolveSdJwtKeyAndAlg(credential, className).second,
                "kty=${key.first} crv=${key.second}"
            )
        }
    }

    @Test
    fun `resolveSdJwtKeyAndAlg infers RS256 for an RSA confirmation key`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("kty" to "rsa"))))

        assertEquals("RS256", resolveSdJwtKeyAndAlg(credential, className).second)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg requires kty on the confirmation jwk`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("crv" to "P-256"))))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveSdJwtKeyAndAlg(credential, className)
        }
        assertEquals("JWK missing 'kty' field", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg rejects a jwk whose algorithm cannot be determined`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("kty" to "EC", "crv" to "P-999"))))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveSdJwtKeyAndAlg(credential, className)
        }
        assertEquals("Cannot determine algorithm from JWK (kty=EC, crv=P-999)", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg requires a cnf claim`() {
        val credential = sdJwt(mapOf("vct" to "employee"))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveSdJwtKeyAndAlg(credential, className)
        }
        assertEquals("cnf missing in SD-JWT", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg requires cnf to carry a jwk or a kid`() {
        val credential = sdJwt(mapOf("cnf" to mapOf("other" to "value")))

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveSdJwtKeyAndAlg(credential, className)
        }
        assertEquals("cnf must contain either 'jwk' or 'kid'", exception.message)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg reads the confirmation key from the jwt ahead of disclosures`() {
        val credential =
            sdJwt(mapOf("cnf" to mapOf("jwk" to mapOf("kty" to "OKP", "crv" to "Ed25519")))) +
                "~disclosure-one~disclosure-two"

        assertEquals("EdDSA", resolveSdJwtKeyAndAlg(credential, className).second)
    }

    @Test
    fun `resolveSdJwtKeyAndAlg infers ES256K for a secp256k1 confirmation kid`() {
        mockkConstructor(DidPublicKeyResolver::class)
        try {
            val mockPublicKey = mockk<java.security.interfaces.ECPublicKey>().apply {
                every { algorithm } returns "EC"
                every { params } returns Curve.SECP256K1.toECParameterSpec()
            }
            every {
                anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
            } returns mockPublicKey

            val kid = "did:key:secp256k1-holder"
            val (keyRef, alg) = resolveSdJwtKeyAndAlg(
                sdJwt(mapOf("cnf" to mapOf("kid" to kid))),
                className
            )

            assertEquals(kid, keyRef)
            assertEquals("ES256K", alg)
        } finally {
            unmockkConstructor(DidPublicKeyResolver::class)
        }
    }

    private fun base64(bytes: ByteArray) = encoder.encodeToString(bytes)

    private fun sdJwt(payload: Map<String, Any>): String {
        val header = base64(getObjectMapper().writeValueAsBytes(mapOf("alg" to "none")))
        val body = base64(getObjectMapper().writeValueAsBytes(payload))
        return "$header.$body.signature"
    }

    @Test
    fun `hashData returns the base64url sha-256 digest by default`() {
        val expected = encoder.encodeToString(
            MessageDigest.getInstance("SHA-256").digest("payload".toByteArray(Charsets.UTF_8))
        )

        assertEquals(expected, hashData("payload"))
    }

    @Test
    fun `hashData honours an explicit algorithm`() {
        val expected = encoder.encodeToString(
            MessageDigest.getInstance("SHA-512").digest("payload".toByteArray(Charsets.UTF_8))
        )

        assertEquals(expected, hashData("payload", "SHA-512"))
    }

    @Test
    fun `hashData is stable across calls`() {
        assertEquals(hashData("payload"), hashData("payload"))
    }

    @Test
    fun `resolveJwksFromUri wraps a non-success status`() {
        mockkObject(NetworkManagerClient)
        every { NetworkManagerClient.sendHTTPRequest(any(), HttpMethod.GET) } returns
            NetworkResponse(500, "boom", headers = emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveJwksFromUri("https://verifier.example/jwks.json", className)
        }

        assertEquals(OpenID4VPErrorCodes.INVALID_REQUEST_OBJECT, exception.errorCode)
        assertTrue(exception.message.contains("Error while fetching jwks information, status code: 500"))
    }

    @Test
    fun `resolveJwksFromUri wraps a transport failure`() {
        mockkObject(NetworkManagerClient)
        every { NetworkManagerClient.sendHTTPRequest(any(), HttpMethod.GET) } throws
            RuntimeException("connection refused")

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveJwksFromUri("https://verifier.example/jwks.json", className)
        }

        assertTrue(exception.message.contains("connection refused"))
    }

    @Test
    fun `resolveJwksFromUri wraps an unparseable body`() {
        mockkObject(NetworkManagerClient)
        every { NetworkManagerClient.sendHTTPRequest(any(), HttpMethod.GET) } returns
            NetworkResponse(200, "not-json", headers = emptyMap())

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveJwksFromUri("https://verifier.example/jwks.json", className)
        }

        assertTrue(exception.message.startsWith("Public key extraction failed"))
    }

    @Test
    fun `encodeToMultibaseBase58btc prefixes the multibase marker`() {
        assertTrue(encodeToMultibaseBase58btc(byteArrayOf(1, 2, 3)).startsWith("z"))
    }

    @Test
    fun `encodeToMultibaseBase58btc encodes leading zero bytes as ones`() {
        assertEquals("z11", encodeToMultibaseBase58btc(byteArrayOf(0, 0)))
        assertTrue(encodeToMultibaseBase58btc(byteArrayOf(0, 1)).startsWith("z1"))
    }

    @Test
    fun `encodeToMultibaseBase58btc encodes an empty array as the bare marker`() {
        assertEquals("z", encodeToMultibaseBase58btc(byteArrayOf()))
    }

    @Test
    fun `encodeToMultibaseBase58btc is deterministic`() {
        val bytes = "signature".toByteArray(Charsets.UTF_8)

        assertEquals(encodeToMultibaseBase58btc(bytes), encodeToMultibaseBase58btc(bytes))
    }

    @Test
    fun `validate accepts a populated value`() {
        validate("client_id", "verifier-1", className)
    }

    @Test
    fun `validate rejects a null value as missing input`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            validate("client_id", null, className)
        }
        assertEquals("Missing Input: client_id param is required", exception.message)
    }

    @Test
    fun `validate rejects empty and literal null values as invalid input`() {
        assertFailsWith<OpenID4VPExceptions.InvalidInput> { validate("client_id", "", className) }
        assertFailsWith<OpenID4VPExceptions.InvalidInput> { validate("client_id", "null", className) }
    }

    @Test
    fun `validate propagates the notifyVerifier flag`() {
        val exception = assertFailsWith<OpenID4VPExceptions.MissingInput> {
            validate("client_id", null, className, notifyVerifier = false)
        }
        assertEquals(false, exception.notifyVerifier)
    }

    @Test
    fun `hexToByteArray round trips with toHex`() {
        val bytes = byteArrayOf(0, 15, 16, 127, -128, -1)

        assertEquals(bytes.toList(), hexToByteArray(bytes.toHex()).toList())
    }

    @Test
    fun `createNestedPath returns null when no nested path is given`() {
        assertNull(createNestedPath("input-1", null, FormatType.LDP_VC))
    }

    @Test
    fun `createNestedPath builds a nested descriptor path`() {
        val nested = createNestedPath("input-1", "$.verifiableCredential[0]", FormatType.LDP_VC)

        assertEquals("input-1", nested?.id)
        assertEquals(FormatType.LDP_VC.value, nested?.format)
        assertEquals("$.verifiableCredential[0]", nested?.path)
    }

    @Test
    fun `createDescriptorMapPath indexes the root path`() {
        assertEquals("$[0]", createDescriptorMapPath(0))
        assertEquals("$[3]", createDescriptorMapPath(3))
    }

    @Test
    fun `generateNonce produces distinct values of the requested entropy`() {
        val first = generateNonce()
        val second = generateNonce()

        assertTrue(first != second)
        assertEquals(16, Base64.getUrlDecoder().decode(first).size)
        assertEquals(32, Base64.getUrlDecoder().decode(generateNonce(32)).size)
    }

    @Test
    fun `getObjectMapper returns the shared instance`() {
        assertTrue(getObjectMapper() === getObjectMapper())
    }

    @Test
    fun `resolveJWSAlgorithm should return correct algorithm for various key types`() {
        data class TestCase(
            val description: String,
            val keyType: String,
            val expectedAlgo: String,
            val setupMock: () -> java.security.PublicKey
        )

        val testCases = listOf(
            TestCase("RSA key", "RSA", "RS256") {
                mockk<java.security.interfaces.RSAPublicKey>().apply {
                    every { algorithm } returns "RSA"
                }
            },
            TestCase("Ed25519 key", "Ed25519", "EdDSA") {
                mockk<java.security.PublicKey>().apply {
                    every { algorithm } returns "Ed25519"
                }
            },
            TestCase("P-256 EC key", "EC", "ES256") {
                mockk<java.security.interfaces.ECPublicKey>().apply {
                    every { algorithm } returns "EC"
                    every { params } returns Curve.P_256.toECParameterSpec()
                }
            },
            TestCase("P-384 EC key", "EC", "ES384") {
                mockk<java.security.interfaces.ECPublicKey>().apply {
                    every { algorithm } returns "EC"
                    every { params } returns Curve.P_384.toECParameterSpec()
                }
            },
            TestCase("P-521 EC key", "EC", "ES512") {
                mockk<java.security.interfaces.ECPublicKey>().apply {
                    every { algorithm } returns "EC"
                    every { params } returns Curve.P_521.toECParameterSpec()
                }
            },
            TestCase("secp256k1 EC key", "EC", "ES256K") {
                mockk<java.security.interfaces.ECPublicKey>().apply {
                    every { algorithm } returns "EC"
                    every { params } returns Curve.SECP256K1.toECParameterSpec()
                }
            }
        )

        mockkConstructor(DidPublicKeyResolver::class)

        try {
            testCases.forEach { testCase ->
                val mockPublicKey = testCase.setupMock()

                every {
                    anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
                } returns mockPublicKey

                val result = resolveJWSAlgorithm("did:test")
                assertEquals(
                    testCase.expectedAlgo,
                    result,
                    "Failed for ${testCase.description}: expected ${testCase.expectedAlgo} but got $result"
                )
            }
        } finally {
            unmockkConstructor(DidPublicKeyResolver::class)
        }
    }

    @Test
    fun `resolveJWSAlgorithm should throw InvalidData for unsupported key algorithm`() {
        mockkConstructor(DidPublicKeyResolver::class)
        mockkStatic(Curve::class)

        try {
            // Test case 1: Generic unsupported key algorithm (DH) - use real TestPublicKey for stable class name
            every {
                anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
            } returns TestPublicKey("DH")

            val dhException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
                resolveJWSAlgorithm("did:test:dh", "TestClass")
            }
            assertOpenId4VPException(
                dhException,
                "Unable to resolve a supported JWS algorithm for key",
                OpenID4VPErrorCodes.INVALID_REQUEST,
                expectedUnderlyingErrorMessage = "Unsupported key type: TestPublicKey"
            )

            // Test case 2: EC key with unsupported/unmapped curve (Curve.forECParameterSpec returns null)
            val mockECKeyUnmappedCurve = mockk<java.security.interfaces.ECPublicKey>().apply {
                every { algorithm } returns "EC"
                every { params } returns mockk<java.security.spec.ECParameterSpec>()
            }
            every {
                anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
            } returns mockECKeyUnmappedCurve
            every {
                Curve.forECParameterSpec(any())
            } returns null

            val ecNullCurveException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
                resolveJWSAlgorithm("did:test:ec-null-curve", "TestClass")
            }
            assertOpenId4VPException(
                ecNullCurveException,
                "Unable to resolve a supported JWS algorithm for key",
                OpenID4VPErrorCodes.INVALID_REQUEST,
                expectedUnderlyingErrorMessage = "Unknown or unsupported EC curve parameters"
            )

            // Test case 3: EC key with resolved curve but unsupported in the when statement
            val mockECKeyUnsupportedCurve = mockk<java.security.interfaces.ECPublicKey>().apply {
                every { algorithm } returns "EC"
                every { params } returns mockk<java.security.spec.ECParameterSpec>()
            }
            every {
                anyConstructed<DidPublicKeyResolver>().resolve(any(), any())
            } returns mockECKeyUnsupportedCurve

            val mockUnsupportedCurve = mockk<Curve>().apply {
                every { name } returns "UNSUPPORTED_CURVE"
            }
            every {
                Curve.forECParameterSpec(any())
            } returns mockUnsupportedCurve

            val ecUnsupportedCurveException = assertFailsWith<OpenID4VPExceptions.InvalidData> {
                resolveJWSAlgorithm("did:test:ec-unsupported-curve", "TestClass")
            }
            assertOpenId4VPException(
                ecUnsupportedCurveException,
                "Unable to resolve a supported JWS algorithm for key",
                OpenID4VPErrorCodes.INVALID_REQUEST,
                expectedUnderlyingErrorMessage = "Unsupported EC curve: UNSUPPORTED_CURVE"
            )
        } finally {
            unmockkConstructor(DidPublicKeyResolver::class)
            unmockkStatic(Curve::class)
        }
    }
}
