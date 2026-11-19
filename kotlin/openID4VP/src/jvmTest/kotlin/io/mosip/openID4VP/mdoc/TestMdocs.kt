package io.mosip.openID4VP.mdoc

import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.common.cborArrayOf
import io.mosip.openID4VP.common.cborMapOf
import io.mosip.openID4VP.common.encodeCbor
import java.security.MessageDigest
import kotlin.coroutines.Continuation
import kotlin.coroutines.EmptyCoroutineContext
import kotlin.coroutines.startCoroutine
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.Map as CborMap

/**
 * SessionTranscriptBytes of a QR + BLE session, as Tuvali hands them over: the shared ISO session
 * vectors (tuvali-iso-tools), so OVP and Tuvali are tested against the same transcript.
 */
internal val qrSessionTranscriptBytes = "d81858c983d8185874a30063312e30018201d818584ba401022001215820640e29c4ccf2256e23872a9911005c601e238ebe1f90380ffce5a0f5aff1496822582036946a61446378ec140beb8523c1832c1058ef7036fb1236be0fae66d8479f340281830201a300f401f50b5045efef742b2c4837a9a3b0e1d05a6917d818584ba40102200121582026b6d3dedcf05caf880b1435ef21954f0de24b83d1b01088223dc4f084c9f8e82258203e2919d95b98683f4904461cdecd046e0b12b482e4fcdb83de4e96bbb4bf41a3f6".hexToBytes()

internal fun String.hexToBytes(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()

/** One data element of a test credential. */
internal class TestElement(val nameSpace: String, val identifier: String, val value: String)

/**
 * Builds mdoc credentials for tests: IssuerSigned with an MSO whose digests match the items, a
 * P-256 deviceKey and a placeholder issuer signature (OVP does not check the issuer signature).
 */
internal object TestMdocs {
    private val deviceKey = cborMapOf(
        1 to 2,
        -1 to 1,
        -2 to ByteArray(32) { 1 },
        -3 to ByteArray(32) { 2 },
    )

    fun issuerSignedItem(digestId: Long, element: TestElement): ByteString {
        val item = cborMapOf(
            "digestID" to digestId,
            "random" to ByteArray(16) { digestId.toByte() },
            "elementIdentifier" to element.identifier,
            "elementValue" to element.value,
        )
        return tag24(encodeCbor(item))
    }

    /** IssuerSigned {nameSpaces, issuerAuth}; [items] replaces the generated items, e.g. to tamper with one. */
    fun issuerSigned(
        docType: String,
        elements: List<TestElement>,
        digestAlgorithm: String = "SHA-256",
        items: ((Map<String, List<ByteString>>) -> Map<String, List<ByteString>>)? = null,
    ): CborMap {
        val generated = elements.withIndex()
            .groupBy({ it.value.nameSpace }, { issuerSignedItem(it.index.toLong(), it.value) })
        val valueDigests = CborMap()
        generated.forEach { (nameSpace, nameSpaceItems) ->
            val digests = CborMap()
            nameSpaceItems.forEachIndexed { _, item ->
                val digestId = digestIdOf(item)
                digests.put(UnsignedInteger(digestId), ByteString(digest(digestAlgorithm, encodeCbor(item))))
            }
            valueDigests.put(UnicodeString(nameSpace), digests)
        }
        val mso = cborMapOf(
            "version" to "1.0",
            "digestAlgorithm" to digestAlgorithm,
            "valueDigests" to valueDigests,
            "deviceKeyInfo" to cborMapOf("deviceKey" to deviceKey),
            "docType" to docType,
        )
        val issuerAuth = cborArrayOf(
            encodeCbor(cborMapOf(1 to -7)),
            cborMapOf(),
            encodeCbor(tag24(encodeCbor(mso))),
            ByteArray(64),
        )
        val nameSpaces = CborMap()
        (items?.invoke(generated) ?: generated).forEach { (nameSpace, nameSpaceItems) ->
            nameSpaces.put(UnicodeString(nameSpace), cborArrayOf(*nameSpaceItems.toTypedArray()))
        }
        return CborMap().apply {
            put(UnicodeString("nameSpaces"), nameSpaces)
            put(UnicodeString("issuerAuth"), issuerAuth)
        }
    }

    fun credential(docType: String, vararg elements: TestElement): ByteArray =
        encodeCbor(issuerSigned(docType, elements.toList()))

    fun digestIdOf(item: ByteString): Long {
        val decoded = io.mosip.openID4VP.common.decodeCbor(item.bytes) as CborMap
        return (decoded.get(UnicodeString("digestID")) as UnsignedInteger).value.toLong()
    }

    fun tag24(encoded: ByteArray): ByteString = ByteString(encoded).apply { setTag(24) }

    private fun digest(algorithm: String, input: ByteArray): ByteArray = MessageDigest.getInstance(algorithm).digest(input)
}

/** Runs [block], which must not really suspend: test signers answer at once. */
internal fun <T> runSuspending(block: suspend () -> T): T {
    var outcome: Result<T>? = null
    block.startCoroutine(Continuation(EmptyCoroutineContext) { outcome = it })
    return checkNotNull(outcome) { "The block suspended" }.getOrThrow()
}

/** Reads a decoded map entry by text key; a missing key fails the test. */
internal operator fun DataItem.get(key: String): DataItem = checkNotNull(getOrNull(key)) { "No \"$key\" in $this" }

internal fun DataItem.getOrNull(key: String): DataItem? = (this as CborMap).get(UnicodeString(key))

internal fun DataItem.items(): List<DataItem> = (this as CborArray).dataItems
