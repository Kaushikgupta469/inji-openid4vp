package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.Array
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.MajorType
import co.nstant.`in`.cbor.model.Map
import co.nstant.`in`.cbor.model.NegativeInteger
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.dcql.evaluator.extractStringFromCborMap
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import java.io.ByteArrayInputStream
import java.security.MessageDigest

// Table 21: digest algorithm identifiers, which are also the JCA names
private val DIGEST_ALGORITHMS = setOf("SHA-256", "SHA-384", "SHA-512")
private const val TAG_ENCODED_CBOR = 24L

internal object MdocCredentialUtils {

    fun getMdocDocTypeAndIssuerSigned(credential: Any, className: String): Triple<String, String, DataItem> {
        val mdocCredential = credential as? String
            ?: throw InvalidData("MDOC credential is not a String",
                className
            )
        val decodedMdoc = decodeCbor(decodeFromBase64Url(mdocCredential)) as? Map
            ?: throw InvalidData("MDOC credential is not a valid CBOR map", className)
        val issuerSigned = getIssuerSigned(decodedMdoc, className)
        val docType = getMdocDocType(issuerSigned, className)

        return Triple(mdocCredential, docType, issuerSigned)
    }
    private fun getMdocDocType(issuerSigned: DataItem, className: String): String {
        val mso: Map = getMso(issuerSigned as? Map
            ?: throw InvalidData("issuerSigned is not a valid CBOR map", className), className)

        return (extractStringFromCborMap(mso, "docType")
            ?: throw InvalidData(
                "docType missing or invalid in credential", className
            ))
    }

    fun getMdocDocType(credential: Any, className: String): String {
        val mdocCredential = credential as? String
            ?: throw InvalidData(
                "MDOC credential is not a String", className
            )
        val decodedMdoc = decodeCbor(decodeFromBase64Url(mdocCredential)) as? Map
            ?: throw InvalidData("MDOC credential is not a valid CBOR map", className)
        val issuerSigned = getIssuerSigned(decodedMdoc, className) as? Map
            ?: throw InvalidData("issuerSigned is not a valid CBOR map", className)
        val mso: Map = getMso(issuerSigned, className)

        return (extractStringFromCborMap(mso, "docType")
            ?: throw InvalidData(
                "docType missing or invalid in credential", className
            ))
    }

    fun getIssuerSigned(decodedMdoc: Map, className: String): DataItem {
        return if (decodedMdoc["issuerAuth"] != null) {
            decodedMdoc
        } else if (decodedMdoc["issuerSigned"] != null) {
            decodedMdoc["issuerSigned"]!!
        } else {
            throw InvalidData(
                "Invalid mDoc structure",
                className
            )
        }
    }

    operator fun DataItem.get(name: String): DataItem? {
        check(this.majorType == MajorType.MAP)
        this as Map
        if (this.keys.contains(UnicodeString(name)))
            return this.get(UnicodeString(name))
        return null
    }

    operator fun DataItem.get(index: Int): DataItem {
        check(this.majorType == MajorType.ARRAY)
        this as Array
        return this.dataItems[index]
    }

    internal fun extractMdocKeyReferenceAndAlg(
        mdocCredential: String,
        className: String
    ): Pair<String, String> {
        val decoded = getDecodedMdocCredential(mdocCredential)

        val issuerSigned = getIssuerSigned(decoded, className) as Map

        val mso = getMso(issuerSigned, className)

        return extractKeyReferenceAndAlgFromMso(mso, className)
    }

    /** The holder key reference (base64url COSE_Key) and the signing algorithm of an MSO's deviceKey. */
    internal fun extractKeyReferenceAndAlgFromMso(mso: Map, className: String): Pair<String, String> {
        val deviceKeyInfo = mso[UnicodeString("deviceKeyInfo")] as? Map
            ?: throw InvalidData("deviceKeyInfo missing", className)

        val deviceKey = deviceKeyInfo[UnicodeString("deviceKey")] as? Map
            ?: throw InvalidData("deviceKey missing", className)

        val keyBytes = encodeCbor(deviceKey)
        val keyRef = encodeToBase64Url(keyBytes)

        val algKey = UnsignedInteger(3)
        val algItem = deviceKey[algKey]

        val alg = if (algItem != null) {
            val coseAlg = when (algItem) {
                is NegativeInteger -> algItem.value.toInt()
                is UnsignedInteger -> algItem.value.toInt()
                else -> throw InvalidData("Invalid alg type", className)
            }

            when (coseAlg) {
                -7 -> "ES256"
                -8 -> "EdDSA"
                else -> throw InvalidData(
                    "Unsupported COSE alg $coseAlg",
                    className
                )
            }
        } else {
            val crvKey = NegativeInteger(-1)
            val crvItem = deviceKey[crvKey]
                ?: throw InvalidData("crv missing for alg inference", className)

            val crv = when (crvItem) {
                is UnsignedInteger -> crvItem.value.toInt()
                else -> throw InvalidData("Invalid crv type", className)
            }

            when (crv) {
                1 -> "ES256"   // P-256
                6 -> "EdDSA"   // Ed25519
                else -> throw InvalidData("Unsupported crv $crv", className)
            }
        }

        return keyRef to alg
    }

    /**
     * Throws InvalidData unless every IssuerSignedItemBytes of [issuerSigned] matches its digest in
     * the [mso] (ISO/IEC 18013-5 clause 9.1.2.5, over the item as it will be sent), and each
     * namespace holds at least one item and no element twice (clause 8.3.2.1.2.2).
     */
    internal fun validateMdocDigests(issuerSigned: Map, mso: Map, className: String) {
        val nameSpaces = issuerSigned[UnicodeString("nameSpaces")] ?: return
        val nameSpaceMap = nameSpaces as? Map ?: throw InvalidData("nameSpaces is not a map", className)
        val digestAlgorithm = (mso[UnicodeString("digestAlgorithm")] as? UnicodeString)?.string
            ?.takeIf { it in DIGEST_ALGORITHMS }
            ?: throw InvalidData("MSO digestAlgorithm is missing or not SHA-256, SHA-384 or SHA-512", className)
        val valueDigests = mso[UnicodeString("valueDigests")] as? Map
            ?: throw InvalidData("MSO valueDigests is missing", className)

        for (nameSpaceKey in nameSpaceMap.keys) {
            val nameSpace = (nameSpaceKey as? UnicodeString)?.string
                ?: throw InvalidData("A namespace is not a text string", className)
            val items = (nameSpaceMap[nameSpaceKey] as? Array)?.dataItems
                ?: throw InvalidData("Namespace $nameSpace does not hold an array", className)
            if (items.isEmpty()) throw InvalidData("Namespace $nameSpace holds no data elements", className)
            val digests = valueDigests[nameSpaceKey] as? Map
                ?: throw InvalidData("The MSO has no digests for namespace $nameSpace", className)
            val seenElements = mutableSetOf<String>()
            for (item in items) {
                val (digestId, element) = readIssuerSignedItem(item, nameSpace, className)
                if (!seenElements.add(element)) {
                    throw InvalidData("Data element $element appears twice in $nameSpace", className)
                }
                val expected = (digests[UnsignedInteger(digestId)] as? ByteString)?.bytes
                    ?: throw InvalidData("The MSO has no digest for $element in $nameSpace", className)
                val actual = MessageDigest.getInstance(digestAlgorithm).digest(encodeCbor(item))
                if (!MessageDigest.isEqual(expected, actual)) {
                    throw InvalidData("Data element $element in $nameSpace does not match its digest in the MSO", className)
                }
            }
        }
    }

    private fun readIssuerSignedItem(item: DataItem, nameSpace: String, className: String): Pair<Long, String> {
        val bytes = item as? ByteString
        if (bytes == null || bytes.tag?.value != TAG_ENCODED_CBOR) {
            throw InvalidData("An item in $nameSpace is not IssuerSignedItemBytes (tag 24)", className)
        }
        val decoded = CborDecoder(ByteArrayInputStream(bytes.bytes)).decode().singleOrNull() as? Map
            ?: throw InvalidData("An item in $nameSpace is not an IssuerSignedItem map", className)
        val digestId = (decoded[UnicodeString("digestID")] as? UnsignedInteger)?.value?.toLong()
            ?: throw InvalidData("An item in $nameSpace has no digestID", className)
        val element = (decoded[UnicodeString("elementIdentifier")] as? UnicodeString)?.string
            ?: throw InvalidData("An item in $nameSpace has no elementIdentifier", className)
        return digestId to element
    }

    internal fun getMso(
        issuerSigned: Map,
        className: String
    ): Map {
        val issuerAuthArray =
            issuerSigned[UnicodeString("issuerAuth")] as? Array
                ?: throw InvalidData("issuerAuth not COSE_Sign1", className)

        if (issuerAuthArray.dataItems.size < 3) {
            throw InvalidData("issuerAuth payload missing", className)
        }

        val payloadBytes = issuerAuthArray.dataItems[2] as? ByteString
            ?: throw InvalidData("issuerAuth payload missing", className)

        val firstDecoded = CborDecoder(ByteArrayInputStream(payloadBytes.bytes)).decode().first()

        // Handle Tag 24 (encoded CBOR)
        val msoDataItem = if (firstDecoded.tag?.value == 24L) {
            val innerBytes = (firstDecoded as? ByteString)?.bytes
                ?: throw InvalidData("Tag 24 inner not bstr", className)

            CborDecoder(ByteArrayInputStream(innerBytes)).decode().first()
        } else {
            firstDecoded
        }

        val mso = msoDataItem as? Map
            ?: throw InvalidData("MSO not map after unwrap", className)
        return mso
    }
}