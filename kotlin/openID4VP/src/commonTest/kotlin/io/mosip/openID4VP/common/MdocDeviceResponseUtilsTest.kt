package io.mosip.openID4VP.common

import co.nstant.`in`.cbor.model.Array as CborArray
import co.nstant.`in`.cbor.model.ByteString
import co.nstant.`in`.cbor.model.UnicodeString
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** The data the mdoc signs for mdoc authentication: ISO/IEC 18013-5 clause 9.1.3.4. */
class MdocDeviceResponseUtilsTest {

    // SessionTranscript for QR engagement: [DeviceEngagementBytes, EReaderKeyBytes, null] (clause 9.1.5.1)
    private val qrTranscript = "83d81841a0d81841a1f6".hexToByteArray()

    @Test
    fun `data to sign is the COSE Sig_structure over DeviceAuthenticationBytes with alg in the protected header`() {
        val dataToSign = MdocDeviceResponseUtils.deviceAuthenticationDataToSign(qrTranscript, "org.iso.18013.5.1.mDL", "ES256")

        val sigStructure = decodeCbor(dataToSign) as CborArray
        assertEquals("Signature1", (sigStructure.dataItems[0] as UnicodeString).string)
        // protected header {1: -7}, ES256
        assertEquals("a10126", (sigStructure.dataItems[1] as ByteString).bytes.toHex())
        assertEquals("", (sigStructure.dataItems[2] as ByteString).bytes.toHex())
        // the payload is DeviceAuthenticationBytes: tag 24 around the encoded DeviceAuthentication
        val payload = decodeCbor((sigStructure.dataItems[3] as ByteString).bytes)
        assertEquals(24L, payload.tag?.value)
    }

    @Test
    fun `DeviceAuthentication holds the label, the transcript, the docType and empty DeviceNameSpacesBytes`() {
        val dataToSign = MdocDeviceResponseUtils.deviceAuthenticationDataToSign(qrTranscript, "org.iso.18013.5.1.mDL", "ES256")

        val deviceAuthentication = deviceAuthenticationOf(dataToSign)
        // 84 = array of four; "DeviceAuthentication"; the transcript; the docType; #6.24(bstr .cbor {})
        val expected = "84" + "74" + "DeviceAuthentication".encodeToByteArray().toHex() +
            qrTranscript.toHex() +
            "75" + "org.iso.18013.5.1.mDL".encodeToByteArray().toHex() +
            "d81841a0"
        assertEquals(expected, deviceAuthentication.toHex())
    }

    @Test
    fun `the session transcript is used exactly as given even when not in its shortest form`() {
        // the same transcript with its array count written in two bytes (98 03) instead of one (83)
        val longFormTranscript = "9803d81841a0d81841a1f6".hexToByteArray()

        val dataToSign = MdocDeviceResponseUtils.deviceAuthenticationDataToSign(longFormTranscript, "org.iso.18013.5.1.mDL", "ES256")

        val deviceAuthentication = deviceAuthenticationOf(dataToSign).toHex()
        assertTrue(deviceAuthentication.contains(longFormTranscript.toHex()))
    }

    /** The DeviceAuthentication bytes inside the tag 24 payload of the Sig_structure. */
    private fun deviceAuthenticationOf(dataToSign: ByteArray): ByteArray {
        val payload = (decodeCbor(dataToSign) as CborArray).dataItems[3] as ByteString
        return (decodeCbor(payload.bytes) as ByteString).bytes
    }

    private fun String.hexToByteArray(): ByteArray = chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
