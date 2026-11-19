package io.mosip.openID4VP.mdoc

import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.SimpleValue
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.common.decodeCbor
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.common.MdocDeviceResponseUtils
import io.mosip.openID4VP.common.toHex
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import co.nstant.`in`.cbor.model.Map as CborMap

/** The DeviceResponse for in-person presentation: ISO/IEC 18013-5 clauses 8.3.2.1.2.2 and 9.1.3. */
class MdocProximityTest {

    private val mdl = "org.iso.18013.5.1.mDL"
    private val mdlNameSpace = "org.iso.18013.5.1"
    private val familyName = TestElement(mdlNameSpace, "family_name", "Doe")
    private val ageOver18 = TestElement(mdlNameSpace, "age_over_18", "true")
    private val signature = ByteArray(64) { 7 }

    /** The encoded SessionTranscript inside SessionTranscriptBytes (tag 24 removed). */
    private val sessionTranscript = (decodeCbor(qrSessionTranscriptBytes) as ByteString).bytes

    private fun build(
        credentials: List<ByteArray>,
        sign: suspend (MdocSigningInput) -> ByteArray = { signature },
    ): ByteArray = runSuspending { MdocProximity.buildDeviceResponse(qrSessionTranscriptBytes, credentials, sign) }

    private fun onlyDocument(response: ByteArray) = decodeCbor(response)["documents"].items().single()

    @Test
    fun `builds a DeviceResponse with version 1_0, the document and status 0`() {
        val response = decodeCbor(build(listOf(TestMdocs.credential(mdl, familyName))))

        assertEquals("1.0", (response["version"] as UnicodeString).string)
        assertEquals(0L, (response["status"] as UnsignedInteger).value.toLong())
        assertEquals(1, response["documents"].items().size)
    }

    @Test
    fun `the document carries the docType of the MSO`() {
        val document = onlyDocument(build(listOf(TestMdocs.credential(mdl, familyName))))

        assertEquals(mdl, (document["docType"] as UnicodeString).string)
    }

    @Test
    fun `issuerSigned items are sent byte for byte as they are in the credential`() {
        val credential = TestMdocs.credential(mdl, familyName, ageOver18)
        val storedItems = decodeCbor(credential)["nameSpaces"][mdlNameSpace].items()

        val document = onlyDocument(build(listOf(credential)))

        val sentItems = document["issuerSigned"]["nameSpaces"][mdlNameSpace].items()
        assertEquals(storedItems.map { encodeCbor(it).toHex() }, sentItems.map { encodeCbor(it).toHex() })
    }

    @Test
    fun `issuerAuth is sent unchanged`() {
        val credential = TestMdocs.credential(mdl, familyName)

        val document = onlyDocument(build(listOf(credential)))

        val stored = encodeCbor(decodeCbor(credential)["issuerAuth"]).toHex()
        assertEquals(stored, encodeCbor(document["issuerSigned"]["issuerAuth"]).toHex())
    }

    @Test
    fun `deviceSigned holds empty DeviceNameSpacesBytes and a detached COSE_Sign1 with the wallet's signature`() {
        val document = onlyDocument(build(listOf(TestMdocs.credential(mdl, familyName))))

        val deviceSigned = document["deviceSigned"]
        assertEquals("d81841a0", encodeCbor(deviceSigned["nameSpaces"]).toHex())
        val sign1 = deviceSigned["deviceAuth"]["deviceSignature"].items()
        // protected header {1: -7} (ES256), empty unprotected header, null payload
        assertEquals("a10126", (sign1[0] as ByteString).bytes.toHex())
        assertEquals(0, (sign1[1] as CborMap).keys.size)
        assertEquals(SimpleValue.NULL, sign1[2])
        assertContentEquals(signature, (sign1[3] as ByteString).bytes)
    }

    @Test
    fun `a response for two documents holds both, in the given order`() {
        val pid = TestMdocs.credential("eu.europa.ec.eudi.pid.1", TestElement("eu.europa.ec.eudi.pid.1", "given_name", "Jane"))

        val response = decodeCbor(build(listOf(TestMdocs.credential(mdl, familyName), pid)))

        val docTypes = response["documents"].items().map { (it["docType"] as UnicodeString).string }
        assertEquals(listOf(mdl, "eu.europa.ec.eudi.pid.1"), docTypes)
    }

    @Test
    fun `with no credentials the response leaves documents out`() {
        // clause 8.3.2.1.2.2: documents is optional and, when present, holds at least one document
        val response = decodeCbor(build(emptyList()))

        assertNull(response.getOrNull("documents"))
        assertEquals(0L, (response["status"] as UnsignedInteger).value.toLong())
    }

    @Test
    fun `the base64url overload gives the same response as the byte version`() {
        val credential = TestMdocs.credential(mdl, familyName)
        val encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(credential)

        val fromString = runSuspending { MdocProximity.buildDeviceResponse(qrSessionTranscriptBytes, listOf(encoded)) { signature } }

        assertEquals(build(listOf(credential)).toHex(), fromString.toHex())
    }

    @Test
    fun `accepts a credential stored as a document holding issuerSigned`() {
        val issuerSigned = TestMdocs.issuerSigned(mdl, listOf(familyName))
        val wrapped = CborMap().apply {
            put(UnicodeString("docType"), UnicodeString(mdl))
            put(UnicodeString("issuerSigned"), issuerSigned)
        }

        val document = onlyDocument(build(listOf(encodeCbor(wrapped))))

        assertEquals(encodeCbor(issuerSigned).toHex(), encodeCbor(document["issuerSigned"]).toHex())
    }

    @Test
    fun `sign is asked once per document with the MSO device key, its algorithm and the device authentication data`() {
        val asked = mutableListOf<MdocSigningInput>()

        build(listOf(TestMdocs.credential(mdl, familyName))) { input ->
            asked += input
            signature
        }

        val input = asked.single()
        assertEquals("ES256", input.signatureAlgorithm)
        assertTrue(input.holderKeyReference.isNotEmpty())
        assertContentEquals(MdocDeviceResponseUtils.deviceAuthenticationDataToSign(sessionTranscript, mdl, "ES256"), input.dataToSign)
    }

    @Test
    fun `an error from sign fails the call with that same error`() {
        val cancelled = IllegalStateException("biometric prompt cancelled")

        val failure = assertFailsWith<IllegalStateException> {
            build(listOf(TestMdocs.credential(mdl, familyName))) { throw cancelled }
        }

        assertSame(cancelled, failure)
    }

    @Test
    fun `an ES256 signature that is not 64 raw bytes is rejected with the expected length`() {
        // a DER-encoded ECDSA signature is 70 to 72 bytes; COSE needs raw r and s
        val failure = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            build(listOf(TestMdocs.credential(mdl, familyName))) { ByteArray(71) }
        }

        assertTrue(failure.message?.contains("ES256 signature must be 64 raw bytes (not DER), got 71") == true)
    }

    @Test
    fun `an Ed448 device key accepts a 114-byte raw signature`() {
        // EdDSA (alg -8) on Ed448 (crv 7), whose signatures are 114 bytes
        val credential = TestMdocs.credential(mdl, familyName, deviceKey = TestMdocs.edDsaDeviceKey(curve = 7, keyBytes = 57))

        val document = onlyDocument(build(listOf(credential)) { ByteArray(114) })

        assertEquals(mdl, (document["docType"] as UnicodeString).string)
    }

    @Test
    fun `an Ed448 device key rejects a 64-byte signature with the expected length`() {
        val credential = TestMdocs.credential(mdl, familyName, deviceKey = TestMdocs.edDsaDeviceKey(curve = 7, keyBytes = 57))

        val failure = assertFailsWith<OpenID4VPExceptions.InvalidData> {
            build(listOf(credential)) { ByteArray(64) }
        }

        assertTrue(failure.message?.contains("EdDSA signature must be 114 raw bytes (not DER), got 64") == true)
    }

    @Test
    fun `an EdDSA device key on an unknown curve is rejected before anything is signed`() {
        // crv 99 is not an EdDSA curve
        val credential = TestMdocs.credential(mdl, familyName, deviceKey = TestMdocs.edDsaDeviceKey(curve = 99, keyBytes = 32))
        var signed = false

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            build(listOf(credential)) { signed = true; signature }
        }
        assertEquals(false, signed)
    }

    @Test
    fun `an item whose digest does not match the MSO is rejected before anything is signed`() {
        // the wallet re-encoded or changed an item while removing the fields not to share
        val tampered = TestMdocs.issuerSigned(mdl, listOf(familyName)) { items ->
            items.mapValues { (_, nameSpaceItems) ->
                nameSpaceItems.map { TestMdocs.issuerSignedItem(TestMdocs.digestIdOf(it), TestElement(mdlNameSpace, "family_name", "Roe")) }
            }
        }
        var signed = false

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            build(listOf(encodeCbor(tampered))) { signed = true; signature }
        }
        assertEquals(false, signed)
    }

    @Test
    fun `a namespace with no items is rejected`() {
        // clause 8.3.2.1.2.2: each namespace holds at least one IssuerSignedItemBytes
        val emptied = TestMdocs.issuerSigned(mdl, listOf(familyName)) { items -> items.mapValues { emptyList() } }

        assertFailsWith<OpenID4VPExceptions.InvalidData> { build(listOf(encodeCbor(emptied))) }
    }

    @Test
    fun `the same element twice in one namespace is rejected`() {
        val repeated = TestMdocs.issuerSigned(mdl, listOf(familyName)) { items -> items.mapValues { (_, it) -> it + it } }

        assertFailsWith<OpenID4VPExceptions.InvalidData> { build(listOf(encodeCbor(repeated))) }
    }

    @Test
    fun `two credentials of the same docType are rejected`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            build(listOf(TestMdocs.credential(mdl, familyName), TestMdocs.credential(mdl, ageOver18)))
        }
    }

    @Test
    fun `an MSO with an unknown digest algorithm is rejected`() {
        val md5 = TestMdocs.issuerSigned(mdl, listOf(familyName), digestAlgorithm = "MD5")

        assertFailsWith<OpenID4VPExceptions.InvalidData> { build(listOf(encodeCbor(md5))) }
    }

    @Test
    fun `a credential that is not CBOR is rejected`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> { build(listOf(byteArrayOf(0x01, 0x02))) }
    }

    @Test
    fun `a bare session transcript without its tag 24 byte string is rejected`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            runSuspending {
                MdocProximity.buildDeviceResponse(sessionTranscript, listOf(TestMdocs.credential(mdl, familyName))) { signature }
            }
        }
    }

    @Test
    fun `session transcript bytes in a byte string without tag 24 are rejected`() {
        val untaggedByteString = encodeCbor(ByteString(sessionTranscript))

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            runSuspending {
                MdocProximity.buildDeviceResponse(untaggedByteString, listOf(TestMdocs.credential(mdl, familyName))) { signature }
            }
        }
    }

    @Test
    fun `an empty session transcript inside tag 24 is rejected before anything is signed`() {
        val empty = encodeCbor(ByteString(ByteArray(0)).apply { setTag(24) })
        var signed = false

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            runSuspending {
                MdocProximity.buildDeviceResponse(empty, listOf(TestMdocs.credential(mdl, familyName))) { signed = true; signature }
            }
        }
        assertEquals(false, signed)
    }

    @Test
    fun `a session transcript of two CBOR items is rejected before anything is signed`() {
        // 01 02: the integers 1 and 2 instead of the 3-item SessionTranscript array
        val twoItems = encodeCbor(ByteString(byteArrayOf(0x01, 0x02)).apply { setTag(24) })
        var signed = false

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            runSuspending {
                MdocProximity.buildDeviceResponse(twoItems, listOf(TestMdocs.credential(mdl, familyName))) { signed = true; signature }
            }
        }
        assertEquals(false, signed)
    }

    @Test
    fun `session transcript bytes under another tag than 24 are rejected`() {
        // tag 25 instead of 24 around the same transcript bytes
        val otherTag = encodeCbor(ByteString(sessionTranscript).apply { setTag(25) })

        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            runSuspending {
                MdocProximity.buildDeviceResponse(otherTag, listOf(TestMdocs.credential(mdl, familyName))) { signature }
            }
        }
    }

    @Test
    fun `a credential followed by more bytes is rejected`() {
        val withTrailingByte = TestMdocs.credential(mdl, familyName) + 0x00

        assertFailsWith<OpenID4VPExceptions.InvalidData> { build(listOf(withTrailingByte)) }
    }

    @Test
    fun `session transcript bytes followed by anything else are rejected`() {
        assertFailsWith<OpenID4VPExceptions.InvalidData> {
            runSuspending {
                MdocProximity.buildDeviceResponse(qrSessionTranscriptBytes + 0x00, listOf(TestMdocs.credential(mdl, familyName))) { signature }
            }
        }
    }
}
