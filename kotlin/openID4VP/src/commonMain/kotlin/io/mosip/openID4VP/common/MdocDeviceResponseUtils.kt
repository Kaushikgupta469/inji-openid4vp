package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.DataItem
import co.nstant.`in`.cbor.model.UnicodeString
import io.mosip.openID4VP.cose.CoseSignature1Utils
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions.InvalidData
import java.io.ByteArrayInputStream
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.Map as CborMap

private const val ARRAY_OF_FOUR: Byte = 0x84.toByte()
private const val TAG_ENCODED_CBOR = 24L

/** Building blocks of an mdoc DeviceResponse, shared by online (OpenID4VP) and in-person presentation. */
internal object MdocDeviceResponseUtils {

    /**
     * What the mdoc signs for mdoc authentication (ISO/IEC 18013-5 clause 9.1.3.4): the COSE
     * Sig_structure over DeviceAuthenticationBytes = #6.24(bstr .cbor ["DeviceAuthentication",
     * SessionTranscript, DocType, DeviceNameSpacesBytes]).
     *
     * [sessionTranscript] is the encoded SessionTranscript and is spliced in exactly as given: the
     * reader rebuilds these bytes from its own copy of the transcript, so they must not be decoded and
     * re-encoded. DeviceNameSpaces is always empty, as Inji returns no device-signed data elements.
     */
    fun deviceAuthenticationDataToSign(sessionTranscript: ByteArray, docType: String, alg: String): ByteArray {
        // written byte by byte so the transcript stays exactly as given: 0x84 starts a 4-item array
        val deviceAuthentication = byteArrayOf(ARRAY_OF_FOUR) +
            encodeCbor(UnicodeString("DeviceAuthentication")) +
            sessionTranscript +
            encodeCbor(UnicodeString(docType)) +
            encodeCbor(emptyDeviceNameSpacesBytes())
        val deviceAuthenticationBytes = taggedCbor24(deviceAuthentication)
        return CoseSignature1Utils.createSignature1Structure(deviceAuthenticationBytes, alg)
    }

    /**
     * The encoded SessionTranscript inside SessionTranscriptBytes (#6.24(bstr .cbor SessionTranscript),
     * clause 9.1.5.1), to be passed to [deviceAuthenticationDataToSign] as it is. Anything other than
     * exactly one tag 24 byte string holding one 3-item array is rejected.
     */
    fun sessionTranscriptFrom(sessionTranscriptBytes: ByteArray, className: String): ByteArray {
        val items = try {
            CborDecoder(ByteArrayInputStream(sessionTranscriptBytes)).decode()
        } catch (exception: Exception) {
            throw InvalidData("Session transcript bytes are not CBOR", className, cause = exception)
        }
        val tagged = items.singleOrNull() as? ByteString
        if (tagged == null || tagged.tag?.value != TAG_ENCODED_CBOR) {
            throw InvalidData("Session transcript bytes must be one tag 24 byte string", className)
        }
        val transcript = try {
            CborDecoder(ByteArrayInputStream(tagged.bytes)).decode().singleOrNull()
        } catch (exception: Exception) {
            throw InvalidData("Session transcript is not CBOR", className, cause = exception)
        }
        if ((transcript as? CborArray)?.dataItems?.size != 3) {
            throw InvalidData("Session transcript must be one 3-item array", className)
        }
        return tagged.bytes
    }

    /**
     * One returned document of a DeviceResponse (clause 8.3.2.1.2.2): {docType, issuerSigned,
     * deviceSigned}. [issuerSigned] is used as given. deviceSigned holds no device-signed data
     * elements and the wallet's [signature] as a detached COSE_Sign1 (clause 9.1.3.6).
     */
    fun document(docType: String, issuerSigned: DataItem, alg: String, signature: ByteArray): CborMap {
        val deviceAuth = cborMapOf("deviceSignature" to CoseSignature1Utils.createCoseSign1(alg, signature))
        val deviceSigned = cborMapOf(
            "deviceAuth" to deviceAuth,
            "nameSpaces" to emptyDeviceNameSpacesBytes()
        )
        return CborMap().apply {
            put(UnicodeString("issuerSigned"), issuerSigned)
            put(UnicodeString("docType"), UnicodeString(docType))
            put(UnicodeString("deviceSigned"), deviceSigned)
        }
    }

    /** DeviceNameSpacesBytes = #6.24(bstr .cbor {}): no device-signed data elements. */
    private fun emptyDeviceNameSpacesBytes(): ByteString = taggedCbor24(CborMap())
}
