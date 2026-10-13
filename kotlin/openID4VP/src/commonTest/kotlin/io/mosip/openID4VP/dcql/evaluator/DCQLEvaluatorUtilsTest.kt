package io.mosip.openID4VP.dcql.evaluator

import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.DoublePrecisionFloat
import co.nstant.`in`.cbor.model.HalfPrecisionFloat
import co.nstant.`in`.cbor.model.Map as CborMap
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.SinglePrecisionFloat
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mockk.every
import io.mockk.mockkStatic
import io.mockk.unmockkAll
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.encodeToBase64Url
import io.mosip.openID4VP.common.getObjectMapper
import io.mosip.openID4VP.common.taggedCbor24
import io.mosip.openID4VP.constants.FormatType
import io.mosip.openID4VP.common.OpenID4VPErrorCodes
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import io.mosip.openID4VP.testData.assertOpenId4VPException
import io.mosip.openID4VP.wallet.Credential
import java.util.Base64
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class DCQLEvaluatorUtilsTest {

    private val encoder = Base64.getUrlEncoder().withoutPadding()

    @BeforeTest
    fun mockBase64() {
        mockkStatic(::decodeFromBase64Url)
        every { decodeFromBase64Url(any()) } answers {
            Base64.getUrlDecoder().decode(firstArg<String>())
        }
        mockkStatic(::encodeToBase64Url)
        every { encodeToBase64Url(any()) } answers { encoder.encodeToString(firstArg<ByteArray>()) }
    }

    @AfterTest
    fun unmockBase64() {
        unmockkAll()
    }

    @Test
    fun `expandCredentialTag throws when ldp credential data is not map`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            expandCredentialTag(Credential(FormatType.LDP_VC, "invalid", "cred-1"))
        }
        assertEquals("Credential data is not in the expected format", exception.message)
    }

    @Test
    fun `expandCredentialTag throws when mdoc credential is not string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            expandCredentialTag(Credential(FormatType.MSO_MDOC, mapOf("docType" to "x"), "cred-1"))
        }
        assertEquals("MDOC credential is not a String", exception.message)
    }

    @Test
    fun `expandCredentialTag throws when sd-jwt credential is not string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            expandCredentialTag(Credential(FormatType.VC_SD_JWT, 123, "cred-1"))
        }
        assertEquals("SD-JWT credential is not a String", exception.message)
    }

    @Test
    fun `convertToProcessedCredentials throws when ldp credential data is not map`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            convertToProcessedCredentials(
                listOf("cred-1"),
                mapOf("cred-1" to Credential(FormatType.LDP_VC, "invalid", "cred-1"))
            )
        }
        assertEquals("Credential data is not in the expected format", exception.message)
    }

    @Test
    fun `convertToProcessedCredentials throws when mdoc credential is not string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            convertToProcessedCredentials(
                listOf("cred-1"),
                mapOf("cred-1" to Credential(FormatType.MSO_MDOC, mapOf("docType" to "x"), "cred-1"))
            )
        }
        assertEquals("MDOC credential is not a String", exception.message)
    }

    @Test
    fun `convertToProcessedCredentials throws when sd-jwt credential is not string`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            convertToProcessedCredentials(
                listOf("cred-1"),
                mapOf("cred-1" to Credential(FormatType.VC_SD_JWT, false, "cred-1"))
            )
        }
        assertEquals("SD-JWT credential is not a String", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer throws when selected element is not object`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf("name"), 1)
        }
        assertEquals("currently selected element(s) is not an object", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer throws when selected element is not array for index`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf(0), mapOf("items" to listOf(1, 2)))
        }
        assertEquals("currently selected element(s) is not an array", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer throws when selected element is not array for null pointer`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf(null), mapOf("items" to listOf(1, 2)))
        }
        assertEquals("currently selected element(s) is not an array", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer throws for unexpected path pointer component`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf(true), mapOf("name" to "alice"))
        }
        assertEquals("Unexpected path pointer component", exception.message)
    }

    @Test
    fun `extractSdJwtPayloadMap throws when sd-jwt credential is empty`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            extractSdJwtPayloadMap("")
        }
        assertEquals("SD-JWT credential is malformed or empty", exception.message)
    }

    @Test
    fun `extractSdJwtPayloadMap throws when sd-jwt jwt part is malformed`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            extractSdJwtPayloadMap("invalidjwt")
        }
        assertEquals("SD-JWT credential JWT part is malformed", exception.message)
    }

    @Test
    fun `expandCredentialTag tags mdoc credential with its docType`() {
        val credential = Credential(FormatType.MSO_MDOC, mdoc(), "cred-1")

        val tagged = expandCredentialTag(credential) as MdocTaggedCredential

        assertEquals("org.iso.18013.5.1.mDL", tagged.doctype)
        assertTrue(tagged.hasCryptographicHolderBinding)
    }

    @Test
    fun `expandCredentialTag marks sd-jwt without cnf as lacking holder binding`() {
        val withBinding = expandCredentialTag(
            DCQLTestFixtures.sdJwtCredential("cred-1", holderBinding = true)
        ) as SdJwtTaggedCredential
        val withoutBinding = expandCredentialTag(
            DCQLTestFixtures.sdJwtCredential("cred-2", holderBinding = false)
        ) as SdJwtTaggedCredential

        assertTrue(withBinding.hasCryptographicHolderBinding)
        assertEquals("https://example.com/employee", withBinding.vct)
        assertEquals(false, withoutBinding.hasCryptographicHolderBinding)
    }

    @Test
    fun `expandCredentialTag defaults vct to empty string when absent`() {
        val payload = encoder.encodeToString(
            getObjectMapper().writeValueAsBytes(mapOf("given_name" to "Alice"))
        )
        val credential = Credential(FormatType.VC_SD_JWT, "header.$payload.signature", "cred-1")

        val tagged = expandCredentialTag(credential) as SdJwtTaggedCredential

        assertEquals("", tagged.vct)
        assertEquals(false, tagged.hasCryptographicHolderBinding)
    }

    @Test
    fun `expandCredentialTag ties ldp holder binding to credentialSubject id`() {
        val withId = expandCredentialTag(DCQLTestFixtures.w3cCredential("cred-1"))
        val withoutId = expandCredentialTag(
            Credential(
                FormatType.LDP_VC,
                mapOf("credentialSubject" to mapOf("given_name" to "Alice")),
                "cred-2"
            )
        )

        assertTrue((withId as W3cTaggedCredential).hasCryptographicHolderBinding)
        assertEquals(false, (withoutId as W3cTaggedCredential).hasCryptographicHolderBinding)
    }

    @Test
    fun `convertToProcessedCredentials skips ids with no matching credential`() {
        val processed = convertToProcessedCredentials(listOf("absent"), emptyMap())

        assertTrue(processed.isEmpty())
    }

    @Test
    fun `convertToProcessedCredentials unwraps every cbor element value type`() {
        val credential = Credential(
            FormatType.MSO_MDOC,
            mdoc(
                elements = listOf(
                    "text" to UnicodeString("Alice"),
                    "positive" to UnsignedInteger(42L),
                    "negative" to NegativeInteger(-7L),
                    "double" to DoublePrecisionFloat(1.5),
                    "single" to SinglePrecisionFloat(2.5f),
                    "half" to HalfPrecisionFloat(3.5f),
                    "yes" to SimpleValue.TRUE,
                    "no" to SimpleValue.FALSE,
                    "bytes" to ByteString(byteArrayOf(1, 2, 3)),
                    "list" to CborArray().apply {
                        add(UnicodeString("a"))
                        add(UnsignedInteger(1L))
                    },
                    "nested" to CborMap().apply {
                        put(UnicodeString("inner"), UnicodeString("value"))
                    }
                )
            ),
            "cred-1"
        )

        val processed = convertToProcessedCredentials(
            listOf("cred-1"),
            mapOf("cred-1" to credential)
        )

        val namespace = (processed["cred-1"] as MdocProcessedCredential)
            .namespaces.getValue("org.iso.18013.5.1")
        assertEquals("Alice", namespace["text"])
        assertEquals(42L, namespace["positive"])
        assertEquals(-7L, namespace["negative"])
        assertEquals(1.5, namespace["double"])
        assertEquals(2.5, namespace["single"])
        assertEquals(3.5, namespace["half"])
        assertEquals(true, namespace["yes"])
        assertEquals(false, namespace["no"])
        assertEquals(listOf(1.toByte(), 2.toByte(), 3.toByte()), (namespace["bytes"] as ByteArray).toList())
        assertEquals(listOf("a", 1L), namespace["list"])
        assertEquals(mapOf("inner" to "value"), namespace["nested"])
    }

    @Test
    fun `convertToProcessedCredentials drops cbor values that unwrap to null`() {
        val credential = Credential(
            FormatType.MSO_MDOC,
            mdoc(elements = listOf("nothing" to SimpleValue.NULL, "text" to UnicodeString("kept"))),
            "cred-1"
        )

        val namespace = (convertToProcessedCredentials(
            listOf("cred-1"),
            mapOf("cred-1" to credential)
        )["cred-1"] as MdocProcessedCredential).namespaces.getValue("org.iso.18013.5.1")

        assertEquals(false, namespace.containsKey("nothing"))
        assertEquals("kept", namespace["text"])
    }

    @Test
    fun `convertToProcessedCredentials rejects an mdoc carrying neither issuerAuth nor issuerSigned`() {
        val root = CborMap().apply { put(UnicodeString("docType"), UnicodeString("mDL")) }
        val credential = Credential(
            FormatType.MSO_MDOC, encoder.encodeToString(encodeCbor(root)), "cred-1"
        )

        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            convertToProcessedCredentials(listOf("cred-1"), mapOf("cred-1" to credential))
        }

        assertOpenId4VPException(
            exception,
            "Invalid mDoc structure",
            OpenID4VPErrorCodes.INVALID_REQUEST
        )
    }

    @Test
    fun `convertToProcessedCredentials yields no namespaces when nameSpaces is absent`() {
        val root = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("mDL"))
            put(UnicodeString("issuerSigned"), CborMap())
        }
        val credential = Credential(
            FormatType.MSO_MDOC, encoder.encodeToString(encodeCbor(root)), "cred-1"
        )

        val processed = convertToProcessedCredentials(
            listOf("cred-1"), mapOf("cred-1" to credential)
        )

        assertTrue((processed["cred-1"] as MdocProcessedCredential).namespaces.isEmpty())
    }

    @Test
    fun `convertToProcessedCredentials ignores namespace entries that are not arrays`() {
        val nameSpaces = CborMap().apply {
            put(UnicodeString("org.iso.18013.5.1"), UnicodeString("not-an-array"))
        }
        val root = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("mDL"))
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("nameSpaces"), nameSpaces)
            })
        }
        val credential = Credential(
            FormatType.MSO_MDOC, encoder.encodeToString(encodeCbor(root)), "cred-1"
        )

        val processed = convertToProcessedCredentials(
            listOf("cred-1"), mapOf("cred-1" to credential)
        )

        assertTrue((processed["cred-1"] as MdocProcessedCredential).namespaces.isEmpty())
    }

    @Test
    fun `convertToProcessedCredentials skips array items that are not tag 24 encoded`() {
        val nameSpaces = CborMap().apply {
            put(UnicodeString("org.iso.18013.5.1"), CborArray().apply {
                add(UnicodeString("untagged"))
                add(element("kept", UnicodeString("value")))
            })
        }
        val root = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("mDL"))
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("nameSpaces"), nameSpaces)
            })
        }
        val credential = Credential(
            FormatType.MSO_MDOC, encoder.encodeToString(encodeCbor(root)), "cred-1"
        )

        val namespace = (convertToProcessedCredentials(
            listOf("cred-1"), mapOf("cred-1" to credential)
        )["cred-1"] as MdocProcessedCredential).namespaces.getValue("org.iso.18013.5.1")

        assertEquals(mapOf<String, Any>("kept" to "value"), namespace)
    }

    @Test
    fun `convertToProcessedCredentials skips elements missing an identifier`() {
        val noIdentifier = CborMap().apply {
            put(UnicodeString("elementValue"), UnicodeString("orphan"))
        }
        val nameSpaces = CborMap().apply {
            put(UnicodeString("org.iso.18013.5.1"), CborArray().apply {
                add(taggedCbor24(noIdentifier))
                add(element("kept", UnicodeString("value")))
            })
        }
        val root = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString("mDL"))
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("nameSpaces"), nameSpaces)
            })
        }
        val credential = Credential(
            FormatType.MSO_MDOC, encoder.encodeToString(encodeCbor(root)), "cred-1"
        )

        val namespace = (convertToProcessedCredentials(
            listOf("cred-1"), mapOf("cred-1" to credential)
        )["cred-1"] as MdocProcessedCredential).namespaces.getValue("org.iso.18013.5.1")

        assertEquals(mapOf<String, Any>("kept" to "value"), namespace)
    }

    @Test
    fun `convertToProcessedCredentials keeps ldp claims verbatim`() {
        val processed = convertToProcessedCredentials(
            listOf("cred-1"),
            mapOf("cred-1" to DCQLTestFixtures.w3cCredential("cred-1"))
        )

        val w3c = processed["cred-1"] as W3cProcessedCredential
        assertEquals(FormatType.LDP_VC, w3c.credentialFormat)
        assertTrue(w3c.claims.containsKey("credentialSubject"))
    }

    @Test
    fun `resolveClaimsPathPointer walks nested object keys`() {
        val claims = mapOf("credentialSubject" to mapOf("given_name" to "Alice"))

        assertEquals(
            "Alice",
            resolveClaimsPathPointer(listOf("credentialSubject", "given_name"), claims)
        )
    }

    @Test
    fun `resolveClaimsPathPointer returns null for an absent key`() {
        assertNull(resolveClaimsPathPointer(listOf("missing"), mapOf("name" to "Alice")))
    }

    @Test
    fun `resolveClaimsPathPointer selects an array element by index`() {
        val claims = mapOf("degrees" to listOf(mapOf("type" to "B.Tech"), mapOf("type" to "M.S.")))

        assertEquals(
            "M.S.",
            resolveClaimsPathPointer(listOf("degrees", 1, "type"), claims)
        )
    }

    @Test
    fun `resolveClaimsPathPointer returns null when index is out of bounds`() {
        val claims = mapOf("degrees" to listOf(mapOf("type" to "B.Tech")))

        assertNull(resolveClaimsPathPointer(listOf("degrees", 5), claims))
        assertNull(resolveClaimsPathPointer(listOf("degrees", -1), claims))
    }

    @Test
    fun `resolveClaimsPathPointer fans out across an array with a null pointer`() {
        val claims = mapOf("degrees" to listOf(mapOf("type" to "B.Tech"), mapOf("type" to "M.S.")))

        assertEquals(
            listOf("B.Tech", "M.S."),
            resolveClaimsPathPointer(listOf("degrees", null, "type"), claims)
        )
    }

    @Test
    fun `resolveClaimsPathPointer returns array elements when path ends with null`() {
        val claims = mapOf("nationalities" to listOf("DE", "FR"))

        assertEquals(
            listOf("DE", "FR"),
            resolveClaimsPathPointer(listOf("nationalities", null), claims)
        )
    }

    @Test
    fun `resolveClaimsPathPointer fans out across nested null pointers`() {
        val claims = mapOf(
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

        assertEquals(
            listOf("Math", "Physics", "Chemistry"),
            resolveClaimsPathPointer(listOf("degrees", null, "subjects", null, "name"), claims)
        )
    }

    @Test
    fun `resolveClaimsPathPointer returns null when a fanned-out claim is absent everywhere`() {
        val claims = mapOf("degrees" to listOf(mapOf("type" to "B.Tech")))

        assertNull(resolveClaimsPathPointer(listOf("degrees", null, "absent"), claims))
    }

    @Test
    fun `resolveClaimsPathPointer throws when fanning out from a non-array`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            resolveClaimsPathPointer(listOf("name", null), mapOf("name" to "Alice"))
        }
        assertEquals("currently selected element(s) is not an array", exception.message)
    }

    @Test
    fun `resolveClaimsPathPointer returns the whole input for an empty path`() {
        val claims = mapOf("name" to "Alice")

        assertEquals(claims, resolveClaimsPathPointer(emptyList(), claims))
    }

    @Test
    fun `extractSdJwtPayloadMap reads the payload of a plain sd-jwt`() {
        val credential = DCQLTestFixtures.sdJwtCredential("cred-1").data as String

        val payload = extractSdJwtPayloadMap(credential)

        assertEquals("https://example.com/employee", payload["vct"])
        assertEquals("Alice", payload["given_name"])
    }

    @Test
    fun `extractSdJwtResolvedClaims merges disclosed claims into the payload`() {
        val nameDisclosure = disclosure("salt1", "given_name", "Alice")
        val credential = sdJwtWithDisclosures(
            payload = mapOf("vct" to "employee", "_sd" to listOf(digestOf(nameDisclosure))),
            disclosures = listOf(nameDisclosure)
        )

        val claims = extractSdJwtResolvedClaims(credential)

        assertEquals("Alice", claims["given_name"])
        assertEquals("employee", claims["vct"])
        assertEquals(false, claims.containsKey("_sd"))
    }

    @Test
    fun `extractSdJwtResolvedClaims resolves disclosures nested inside objects`() {
        val innerDisclosure = disclosure("salt2", "street", "Main St")
        val credential = sdJwtWithDisclosures(
            payload = mapOf(
                "address" to mapOf("_sd" to listOf(digestOf(innerDisclosure)), "city" to "Berlin")
            ),
            disclosures = listOf(innerDisclosure)
        )

        val claims = extractSdJwtResolvedClaims(credential)

        @Suppress("UNCHECKED_CAST")
        val address = claims["address"] as Map<String, Any>
        assertEquals("Main St", address["street"])
        assertEquals("Berlin", address["city"])
    }

    @Test
    fun `extractSdJwtResolvedClaims resolves a disclosure whose value is an object`() {
        val objectDisclosure = disclosure("salt3", "address", mapOf("city" to "Berlin"))
        val credential = sdJwtWithDisclosures(
            payload = mapOf("_sd" to listOf(digestOf(objectDisclosure))),
            disclosures = listOf(objectDisclosure)
        )

        val claims = extractSdJwtResolvedClaims(credential)

        assertEquals(mapOf("city" to "Berlin"), claims["address"])
    }

    @Test
    fun `extractSdJwtResolvedClaims strips the _sd_alg bookkeeping claim`() {
        val credential = sdJwtWithDisclosures(
            payload = mapOf("vct" to "employee", "_sd_alg" to "sha-256"),
            disclosures = emptyList()
        )

        val claims = extractSdJwtResolvedClaims(credential)

        assertEquals(false, claims.containsKey("_sd_alg"))
        assertEquals("employee", claims["vct"])
    }

    @Test
    fun `extractSdJwtResolvedClaims ignores undecodable and malformed disclosures`() {
        val valid = disclosure("salt4", "given_name", "Alice")
        val tooShort = encoder.encodeToString(
            getObjectMapper().writeValueAsBytes(listOf("salt", "only_two"))
        )
        val credential = sdJwtWithDisclosures(
            payload = mapOf("_sd" to listOf(digestOf(valid))),
            disclosures = listOf(valid, tooShort, "!!!not-base64!!!")
        )

        val claims = extractSdJwtResolvedClaims(credential)

        assertEquals("Alice", claims["given_name"])
    }

    @Test
    fun `extractSdJwtResolvedClaims leaves undisclosed digests unresolved`() {
        val credential = sdJwtWithDisclosures(
            payload = mapOf("vct" to "employee", "_sd" to listOf("digest-with-no-disclosure")),
            disclosures = emptyList()
        )

        val claims = extractSdJwtResolvedClaims(credential)

        assertEquals(mapOf<String, Any>("vct" to "employee"), claims)
    }

    @Test
    fun `extractSdJwtResolvedClaims throws when the jwt part is malformed`() {
        val exception = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            extractSdJwtResolvedClaims("malformed~disclosure")
        }
        assertEquals("SD-JWT credential JWT part is malformed", exception.message)
    }

    @Test
    fun `convertToProcessedCredentials yields no namespaces when issuerSigned is not a map`() {
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), UnicodeString("not-a-map"))
        }
        val credential = Credential(
            FormatType.MSO_MDOC, encoder.encodeToString(encodeCbor(root)), "cred-1"
        )

        val processed = convertToProcessedCredentials(
            listOf("cred-1"), mapOf("cred-1" to credential)
        )

        assertTrue((processed["cred-1"] as MdocProcessedCredential).namespaces.isEmpty())
    }

    @Test
    fun `convertToProcessedCredentials skips a tag 24 item whose payload is not decodable cbor`() {
        val broken = ByteString(byteArrayOf(0x9f.toByte())).apply { setTag(24L) }
        val nameSpaces = CborMap().apply {
            put(UnicodeString("org.iso.18013.5.1"), CborArray().apply {
                add(broken)
                add(element("kept", UnicodeString("value")))
            })
        }
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("issuerAuth"), issuerAuth("mDL"))
                put(UnicodeString("nameSpaces"), nameSpaces)
            })
        }
        val credential = Credential(
            FormatType.MSO_MDOC, encoder.encodeToString(encodeCbor(root)), "cred-1"
        )

        val namespace = (convertToProcessedCredentials(
            listOf("cred-1"), mapOf("cred-1" to credential)
        )["cred-1"] as MdocProcessedCredential).namespaces.getValue("org.iso.18013.5.1")

        assertEquals(mapOf<String, Any>("kept" to "value"), namespace)
    }

    @Test
    fun `convertToProcessedCredentials skips a tag 24 item that is not a byte string`() {
        val taggedText = UnicodeString("tagged-but-not-bytes").apply { setTag(24L) }
        val nameSpaces = CborMap().apply {
            put(UnicodeString("org.iso.18013.5.1"), CborArray().apply {
                add(taggedText)
                add(element("kept", UnicodeString("value")))
            })
        }
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("issuerAuth"), issuerAuth("mDL"))
                put(UnicodeString("nameSpaces"), nameSpaces)
            })
        }
        val credential = Credential(
            FormatType.MSO_MDOC, encoder.encodeToString(encodeCbor(root)), "cred-1"
        )

        val namespace = (convertToProcessedCredentials(
            listOf("cred-1"), mapOf("cred-1" to credential)
        )["cred-1"] as MdocProcessedCredential).namespaces.getValue("org.iso.18013.5.1")

        assertEquals(mapOf<String, Any>("kept" to "value"), namespace)
    }

    private fun element(identifier: String, value: DataItem): DataItem =
        taggedCbor24(CborMap().apply {
            put(UnicodeString("elementIdentifier"), UnicodeString(identifier))
            put(UnicodeString("elementValue"), value)
        })

    private fun mdoc(
        docType: String = "org.iso.18013.5.1.mDL",
        namespace: String = "org.iso.18013.5.1",
        elements: List<Pair<String, DataItem>> = listOf("given_name" to UnicodeString("Alice"))
    ): String {
        val items = CborArray().apply {
            elements.forEach { (identifier, value) -> add(element(identifier, value)) }
        }
        val root = CborMap().apply {
            put(UnicodeString("issuerSigned"), CborMap().apply {
                put(UnicodeString("issuerAuth"), issuerAuth(docType))
                put(UnicodeString("nameSpaces"), CborMap().apply {
                    put(UnicodeString(namespace), items)
                })
            })
        }
        return encoder.encodeToString(encodeCbor(root))
    }

    private fun issuerAuth(docType: String): CborArray {
        val mso = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString(docType))
        }
        return CborArray().apply {
            add(ByteString(byteArrayOf()))
            add(CborMap())
            add(taggedCbor24(mso))
            add(ByteString(byteArrayOf()))
        }
    }

    private fun disclosure(salt: String, claimName: String, claimValue: Any): String =
        encoder.encodeToString(
            getObjectMapper().writeValueAsBytes(listOf(salt, claimName, claimValue))
        )

    private fun digestOf(disclosure: String): String {
        val hash = java.security.MessageDigest.getInstance("SHA-256")
            .digest(disclosure.toByteArray(Charsets.UTF_8))
        return encoder.encodeToString(hash)
    }

    private fun sdJwtWithDisclosures(
        payload: Map<String, Any>,
        disclosures: List<String>
    ): String {
        val header = encoder.encodeToString(
            getObjectMapper().writeValueAsBytes(mapOf("alg" to "none"))
        )
        val encodedPayload = encoder.encodeToString(getObjectMapper().writeValueAsBytes(payload))
        return (listOf("$header.$encodedPayload.signature") + disclosures).joinToString("~")
    }
}
