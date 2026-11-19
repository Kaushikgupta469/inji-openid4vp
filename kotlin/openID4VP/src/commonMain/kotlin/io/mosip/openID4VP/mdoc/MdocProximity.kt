package io.mosip.openID4VP.mdoc

import co.nstant.`in`.cbor.CborDecoder
import co.nstant.`in`.cbor.model.UnicodeString
import co.nstant.`in`.cbor.model.UnsignedInteger
import io.mosip.openID4VP.common.MdocCredentialUtils
import io.mosip.openID4VP.common.MdocDeviceResponseUtils
import io.mosip.openID4VP.common.decodeFromBase64Url
import io.mosip.openID4VP.common.encodeCbor
import io.mosip.openID4VP.exceptions.OpenID4VPExceptions
import java.io.ByteArrayInputStream
import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.Map as CborMap

private const val className = "MdocProximity"
private const val DEVICE_RESPONSE_VERSION = "1.0"
private const val STATUS_OK = 0L

// raw signature length for each supported device key algorithm: r ‖ s on P-256, and Ed25519
private val SIGNATURE_BYTES_BY_ALGORITHM = mapOf("ES256" to 64, "EdDSA" to 64)

/**
 * Builds an ISO/IEC 18013-5 DeviceResponse (8.3.2.1.2.2). Credentials must already be
 * filtered without altering issued item bytes. Retained MSO digests are validated before
 * the wallet signs DeviceAuthentication with each credential's device key (9.1.3).
 */
object MdocProximity {

    /**
     * [sessionTranscriptBytes] are the SessionTranscriptBytes of the session (#6.24 around the
     * SessionTranscript), exactly as the transport provides them. [credentials] are mdoc
     * credentials as CBOR, one per docType. An error thrown by [sign] fails the call unchanged.
     */
    suspend fun buildDeviceResponse(
        sessionTranscriptBytes: ByteArray,
        credentials: List<ByteArray>,
        sign: suspend (MdocSigningInput) -> ByteArray,
    ): ByteArray {
        val sessionTranscript = MdocDeviceResponseUtils.sessionTranscriptFrom(sessionTranscriptBytes, className)
        val documents = mutableListOf<CborMap>()
        val docTypes = mutableSetOf<String>()
        for (credential in credentials) {
            val issuerSigned = issuerSignedOf(credential)
            val mso = MdocCredentialUtils.getMso(issuerSigned, className)
            MdocCredentialUtils.validateMdocDigests(issuerSigned, mso, className)
            val docType = (mso[UnicodeString("docType")] as? UnicodeString)?.string
                ?: throw invalid("docType missing or invalid in the MSO")
            if (!docTypes.add(docType)) throw invalid("Duplicate Mdoc Credentials with same doctype found")
            val (holderKeyReference, algorithm) = MdocCredentialUtils.extractKeyReferenceAndAlgFromMso(mso, className)

            val expectedBytes = SIGNATURE_BYTES_BY_ALGORITHM[algorithm]
                ?: throw invalid("Unsupported device key algorithm $algorithm")

            val dataToSign = MdocDeviceResponseUtils.deviceAuthenticationDataToSign(sessionTranscript, docType, algorithm)
            val signature = sign(MdocSigningInput(holderKeyReference, algorithm, dataToSign))
            if (signature.size != expectedBytes) {
                throw invalid("$algorithm signature must be $expectedBytes raw bytes (not DER), got ${signature.size}")
            }
            documents += MdocDeviceResponseUtils.document(docType, issuerSigned, algorithm, signature)
        }

        val response = CborMap().apply {
            put(UnicodeString("version"), UnicodeString(DEVICE_RESPONSE_VERSION))
            // documents, when present, holds at least one document
            if (documents.isNotEmpty()) put(UnicodeString("documents"), CborArray().apply { documents.forEach { add(it) } })
            put(UnicodeString("status"), UnsignedInteger(STATUS_OK))
        }
        return encodeCbor(response)
    }

    /** As [buildDeviceResponse], with each credential given as base64url-encoded CBOR. */
    @JvmName("buildDeviceResponseFromBase64Url")
    suspend fun buildDeviceResponse(
        sessionTranscriptBytes: ByteArray,
        credentials: List<String>,
        sign: suspend (MdocSigningInput) -> ByteArray,
    ): ByteArray {
        val decoded = credentials.map { credential ->
            try {
                decodeFromBase64Url(credential)
            } catch (exception: IllegalArgumentException) {
                throw invalid("mdoc credential is not base64url", exception)
            }
        }
        return buildDeviceResponse(sessionTranscriptBytes, decoded, sign)
    }

    private fun issuerSignedOf(credential: ByteArray): CborMap = try {
        val decoded = CborDecoder(ByteArrayInputStream(credential)).decode().singleOrNull() as? CborMap
            ?: throw invalid("mdoc credential is not one CBOR map")
        MdocCredentialUtils.getIssuerSigned(decoded, className) as? CborMap ?: throw invalid("issuerSigned is not a CBOR map")
    } catch (exception: OpenID4VPExceptions) {
        throw exception
    } catch (exception: Exception) {
        throw invalid("mdoc credential could not be read: ${exception.message}", exception)
    }

    private fun invalid(message: String, cause: Throwable? = null) =
        OpenID4VPExceptions.InvalidData(message, className, cause = cause)
}
