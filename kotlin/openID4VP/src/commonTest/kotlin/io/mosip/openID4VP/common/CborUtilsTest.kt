package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.model.*
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.Map
import io.mockk.*
import kotlin.test.*
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnsignedInteger
import co.nstant.`in`.cbor.model.Map as CborMap
import io.mosip.openID4VP.authorizationRequest.clientMetadata.Jwk
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class CborUtilsTest {



    @AfterTest
    fun tearDown() {
        clearAllMocks()
    }

    @Test
    fun `taggedCbor24 wraps already encoded bytes exactly as given`() {
        // an array of 3 with its count in the long form (98 03), which re-encoding would shorten to 83
        val encoded = byteArrayOf(0x98.toByte(), 0x03, 0xF6.toByte(), 0xF6.toByte(), 0xF6.toByte())

        val tagged = taggedCbor24(encoded)

        // tag 24, then a byte string of length 5, then the bytes unchanged
        assertContentEquals(byteArrayOf(0xD8.toByte(), 0x18, 0x45) + encoded, tagged)
    }

    @Test
    fun `encodeCbor and decodeCbor should be inverse operations`() {
        val testString = UnicodeString("test")
        val encoded = encodeCbor(testString)
        val decoded = decodeCbor(encoded)

        assertEquals(testString.toString(), decoded.toString())
    }

    @Test
    fun `should create cbor array with different types of data`() {
        val result = cborArrayOf(
            "string",
            123,
            123L,
            1.23,
            "hello".toByteArray(),
            UnicodeString("unicode"),
            null
        )

        assertTrue(result is Array)
        val array = result as Array
        assertEquals(7, array.dataItems.size)
        assertEquals("string", array.dataItems[0].toString())
        assertEquals("123", array.dataItems[1].toString())
        assertEquals("123", array.dataItems[2].toString())
        assertEquals("1.23", array.dataItems[3].toString())
        assertTrue(array.dataItems[4] is ByteString)
        assertEquals("unicode", array.dataItems[5].toString())
        assertNull(array.dataItems[6])
    }

    @Test
    fun `cborArrayOf should throw exception for unsupported type`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            cborArrayOf(Object())
        }
        assertTrue(exception.message!!.contains("Unsupported type"))
    }

    @Test
    fun `should create cbor map with different types`() {
        val map = cborMapOf(
            "key1" to "value1",
            123 to 456,
            "key3" to 789L,
            "key4" to 1.23,
            "key5" to "hello".toByteArray(),
            "key6" to UnicodeString("unicode"),
            "key7" to null
        )

        assertTrue(map is Map)
        val cborMap = map as Map
        assertEquals(7, cborMap.keys.size)

        val key1 = UnicodeString("key1")
        assertEquals("value1", cborMap.get(key1).toString())

        val key2 = UnsignedInteger(123)
        assertEquals("456", cborMap.get(key2).toString())

        val key7 = UnicodeString("key7")
        assertNull(cborMap.get(key7))
    }

    @Test
    fun `cborMapOf should throw exception for null key`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            cborMapOf(null to "value")
        }
        assertEquals("Key cannot be null", exception.message)
    }

    @Test
    fun `cborMapOf should throw exception for unsupported key type`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            cborMapOf(Object() to "value")
        }
        assertTrue(exception.message!!.contains("Unsupported key type"))
    }

    @Test
    fun `cborMapOf should throw exception for unsupported value type`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            cborMapOf("key" to Object())
        }
        assertTrue(exception.message!!.contains("Unsupported value type"))
    }

    @Test
    fun `createHashedDataItem should create ByteString`() {
        val result = createHashedDataItem("test", 123)
        assertTrue(result is ByteString)
        assertEquals(32, result.bytes.size)
    }

    @Test
    fun `generateHash should produce consistent hashes`() {
        val input = UnicodeString("test")
        val hash1 = generateHash(input)
        val hash2 = generateHash(input)

        assertContentEquals(hash1, hash2)
        assertEquals(32, hash1.size)
    }


    @Test
    fun `mapSigningAlgorithmToProtectedAlg should return correct value for supported algorithm`() {
        assertEquals(-7L, mapSigningAlgorithmToProtectedAlg("ES256"))
        assertEquals(-35L, mapSigningAlgorithmToProtectedAlg("ES384"))
        assertEquals(-36L, mapSigningAlgorithmToProtectedAlg("ES512"))
        assertEquals(-8L, mapSigningAlgorithmToProtectedAlg("EdDSA"))
        assertEquals(-37L, mapSigningAlgorithmToProtectedAlg("PS256"))
        assertEquals(-38L, mapSigningAlgorithmToProtectedAlg("PS384"))
        assertEquals(-39L, mapSigningAlgorithmToProtectedAlg("PS512"))
    }

    @Test
    fun `mapSigningAlgorithmToProtectedAlg should throw exception for unsupported algorithm`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            mapSigningAlgorithmToProtectedAlg("UNSUPPORTED")
        }
        assertTrue(exception.message!!.contains("Unsupported signing algorithm: UNSUPPORTED"))
    }

    private fun sha256(input: String) =
        MessageDigest.getInstance("SHA-256").digest(input.toByteArray(Charsets.UTF_8))

    @Test
    fun `computes an EC thumbprint over the canonical crv kty x y members`() {
        val jwk = Jwk(kty = "EC", crv = "P-256", x = "x-value", y = "y-value")

        val expected = sha256("""{"crv":"P-256","kty":"EC","x":"x-value","y":"y-value"}""")

        assertContentEquals(expected, jwkThumbprintBytes(jwk))
    }

    @Test
    fun `computes an OKP thumbprint over the canonical crv kty x members`() {
        val jwk = Jwk(kty = "OKP", crv = "Ed25519", x = "x-value")

        val expected = sha256("""{"crv":"Ed25519","kty":"OKP","x":"x-value"}""")

        assertContentEquals(expected, jwkThumbprintBytes(jwk))
    }

    @Test
    fun `rejects RSA keys which the Jwk model cannot represent`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            jwkThumbprintBytes(Jwk(kty = "RSA", x = "x-value"))
        }
        assertEquals("RSA key type not supported in current Jwk model", exception.message)
    }

    @Test
    fun `rejects an unsupported key type`() {
        val exception = assertFailsWith<IllegalArgumentException> {
            jwkThumbprintBytes(Jwk(kty = "oct", x = "x-value"))
        }
        assertEquals("Unsupported key type for JWK thumbprint: oct", exception.message)
    }

    @Test
    fun `wraps the thumbprint as a cbor byte string`() {
        val jwk = Jwk(kty = "OKP", crv = "Ed25519", x = "x-value")

        assertContentEquals(jwkThumbprintBytes(jwk), toJWKThumbprintBstr(jwk).bytes)
    }

    @Test
    fun `cborMapOf encodes negative and positive ints with the matching cbor type`() {
        val map = cborMapOf("positive" to 7, "negative" to -7) as CborMap

        val positive = map[co.nstant.`in`.cbor.model.UnicodeString("positive")]
        val negative = map[co.nstant.`in`.cbor.model.UnicodeString("negative")]

        assertEquals(UnsignedInteger(7L), positive)
        assertEquals(NegativeInteger(-7L), negative)
    }

    @Test
    fun `cborMapOf encodes negative and positive longs with the matching cbor type`() {
        val map = cborMapOf("positive" to 7L, "negative" to -7L) as CborMap

        assertEquals(
            UnsignedInteger(7L),
            map[co.nstant.`in`.cbor.model.UnicodeString("positive")]
        )
        assertEquals(
            NegativeInteger(-7L),
            map[co.nstant.`in`.cbor.model.UnicodeString("negative")]
        )
    }
    @Test
    fun `encodeWithCborTag24 should encode data with CBOR tag 24`() {
        val input = UnicodeString("test")
        val result = taggedCbor24(input)
        
        // Verify result is not empty
        assertTrue(result.isNotEmpty())
        
        // Decode and verify tag 24 is present
        val decoded = decodeCbor(result)
        assertTrue(decoded is ByteString)
        assertEquals(24L, decoded.tag?.value)
        
        // Verify the inner content is correct
        val innerBytes = (decoded as ByteString).bytes
        val innerDecoded = decodeCbor(innerBytes)
        assertEquals("test", innerDecoded.toString())
    }

}
